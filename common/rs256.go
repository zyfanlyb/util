package main

// rs256.go —— 认证中心(IdP)用 RSA 私钥签发 JWT、业务系统用公钥验签的最小可用实现。
//
// 设计要点:
//   1. 私钥只在认证中心;业务系统只持有公钥(通过 JWKS 端点拉取)。
//   2. 验签前先做 alg 白名单校验,只放行 RS256 —— 挡住 alg:none 和 RS256→HS256 算法混淆攻击。
//   3. payload 只是 base64 编码,不是加密,禁止放敏感字段。
//   4. 只用标准库,零外部依赖。go run rs256.go 可直接运行。

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"
)

const (
	AlgRS256       = "RS256"
	defaultLeeway  = time.Minute // 允许的时钟偏差
	defaultKeyBits = 2048        // RSA 密钥长度,2048 起步
)

// ============================ 错误定义 ============================

var (
	ErrInvalidFormat    = errors.New("token 格式非法(必须是 header.payload.signature 三段)")
	ErrAlgNotAllowed    = errors.New("alg 不在白名单内,拒绝验签")
	ErrInvalidSignature = errors.New("签名校验失败,token 被篡改或不是本认证中心签发")
	ErrExpired          = errors.New("token 已过期")
	ErrNotYetValid      = errors.New("token 尚未生效(nbf)")
	ErrIssuedInFuture   = errors.New("token 签发时间在未来(iat)")
	ErrInvalidIssuer    = errors.New("iss 不匹配")
	ErrInvalidAudience  = errors.New("aud 不匹配")
	ErrUnknownKID       = errors.New("jwks 中找不到对应 kid")
)

// ============================ base64url 工具 ============================
// JWT 用的是 base64url 且去掉 = padding

func b64uEncode(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func b64uDecode(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

// ============================ 密钥仓库(认证中心持有) ============================

type KeyStore struct {
	KID     string          // 密钥 ID,轮换时靠它区分新旧密钥
	Private *rsa.PrivateKey // 仅认证中心持有,绝不外泄,建议放 KMS/HSM
	Public  *rsa.PublicKey  // 可公开分发
}

func NewKeyStore() (*KeyStore, error) {
	priv, err := rsa.GenerateKey(rand.Reader, defaultKeyBits)
	if err != nil {
		return nil, fmt.Errorf("生成 RSA 密钥失败: %w", err)
	}
	// kid 用随机串即可,轮换时换成新串,新旧公钥在 JWKS 里共存一段时间
	id := make([]byte, 8)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	return &KeyStore{
		KID:     b64uEncode(id),
		Private: priv,
		Public:  &priv.PublicKey,
	}, nil
}

// ============================ Claims ============================

type Claims map[string]any

func (c Claims) GetString(k string) (string, bool) {
	v, ok := c[k]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

func (c Claims) GetInt64(k string) (int64, bool) {
	switch n := c[k].(type) {
	case float64: // JSON 数字默认解析成 float64
		return int64(n), true
	case int64:
		return n, true
	case int:
		return int64(n), true
	case json.Number:
		v, err := n.Int64()
		return v, err == nil
	}
	return 0, false
}

// ============================ 签发(认证中心) ============================

type Header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ,omitempty"`
	KID string `json:"kid"`
}

// Sign 用私钥签发一个 RS256 JWT。
// exp 未指定时默认 15 分钟有效;iat 未指定时自动填当前时间。
func (ks *KeyStore) Sign(claims Claims) (string, error) {
	if ks.Private == nil {
		return "", errors.New("缺少私钥,只有认证中心能签发 token")
	}

	now := time.Now()
	if _, ok := claims["iat"]; !ok {
		claims["iat"] = now.Unix()
	}
	if _, ok := claims["exp"]; !ok {
		claims["exp"] = now.Add(15 * time.Minute).Unix()
	}

	hdr := Header{Alg: AlgRS256, Typ: "JWT", KID: ks.KID}
	hdrJSON, err := json.Marshal(hdr)
	if err != nil {
		return "", err
	}
	plJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	signingInput := b64uEncode(hdrJSON) + "." + b64uEncode(plJSON)
	digest := sha256.Sum256([]byte(signingInput))

	// RS256 = RSASSA-PKCS1-v1_5 + SHA-256,必须是 PKCS1v15(PSS 对应的是 PS256)
	sig, err := rsa.SignPKCS1v15(rand.Reader, ks.Private, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + b64uEncode(sig), nil
}

// ============================ 验签(业务系统) ============================

type VerifyOptions struct {
	Issuer   string        // 为空则不校验 iss
	Audience string        // 为空则不校验 aud
	Leeway   time.Duration // 时钟偏差容忍,默认 1 分钟
}

// Verify 用公钥验签。业务系统只调这个,永远拿不到签发能力。
func Verify(token string, pub *rsa.PublicKey, opts VerifyOptions) (Claims, error) {
	if opts.Leeway == 0 {
		opts.Leeway = defaultLeeway
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidFormat
	}

	// --- 第 1 步:解析 header,先卡 alg 白名单 ---
	// 这一步必须在验签之前。否则攻击者把 alg 改成 none / HS256 就能绕过。
	hdrBytes, err := b64uDecode(parts[0])
	if err != nil {
		return nil, ErrInvalidFormat
	}
	var hdr Header
	if err := json.Unmarshal(hdrBytes, &hdr); err != nil {
		return nil, ErrInvalidFormat
	}
	if hdr.Alg != AlgRS256 {
		// 白名单里永远不要加 HS256 和 none
		return nil, ErrAlgNotAllowed
	}
	if hdr.Typ != "" && !strings.EqualFold(hdr.Typ, "JWT") {
		return nil, ErrInvalidFormat
	}

	// --- 第 2 步:验签 ---
	sig, err := b64uDecode(parts[2])
	if err != nil {
		return nil, ErrInvalidFormat
	}
	if len(sig) == 0 {
		return nil, ErrInvalidSignature
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
		return nil, ErrInvalidSignature
	}

	// --- 第 3 步:签名通过后才解析 payload ---
	plBytes, err := b64uDecode(parts[1])
	if err != nil {
		return nil, ErrInvalidFormat
	}
	var claims Claims
	if err := json.Unmarshal(plBytes, &claims); err != nil {
		return nil, ErrInvalidFormat
	}

	// --- 第 4 步:标准声明校验 ---
	now := time.Now()
	if exp, ok := claims.GetInt64("exp"); ok {
		if now.After(time.Unix(exp, 0).Add(opts.Leeway)) {
			return nil, ErrExpired
		}
	}
	if nbf, ok := claims.GetInt64("nbf"); ok {
		if now.Before(time.Unix(nbf, 0).Add(-opts.Leeway)) {
			return nil, ErrNotYetValid
		}
	}
	if iat, ok := claims.GetInt64("iat"); ok {
		if now.Before(time.Unix(iat, 0).Add(-opts.Leeway)) {
			return nil, ErrIssuedInFuture
		}
	}
	if opts.Issuer != "" {
		if iss, _ := claims.GetString("iss"); iss != opts.Issuer {
			return nil, ErrInvalidIssuer
		}
	}
	if opts.Audience != "" {
		if aud, _ := claims.GetString("aud"); aud != opts.Audience {
			return nil, ErrInvalidAudience
		}
	}
	return claims, nil
}

// ============================ JWKS:公钥分发 ============================

type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"` // modulus,base64url
	E   string `json:"e"` // exponent,base64url,通常是 AQAB(65537)
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

func (ks *KeyStore) PublicJWKS() JWKS {
	return JWKS{Keys: []JWK{{
		Kty: "RSA",
		Use: "sig",
		Alg: AlgRS256,
		Kid: ks.KID,
		N:   b64uEncode(ks.Public.N.Bytes()),
		E:   b64uEncode(big.NewInt(int64(ks.Public.E)).Bytes()),
	}}}
}

// ParseRSAPublicKey 把 JWK 还原成公钥(业务系统拉取 JWKS 后使用)。
func ParseRSAPublicKey(jwk JWK) (*rsa.PublicKey, error) {
	if jwk.Kty != "RSA" {
		return nil, errors.New("不是 RSA 密钥")
	}
	nBytes, err := b64uDecode(jwk.N)
	if err != nil {
		return nil, err
	}
	eBytes, err := b64uDecode(jwk.E)
	if err != nil {
		return nil, err
	}
	e := new(big.Int).SetBytes(eBytes)
	if !e.IsInt64() || e.Int64() <= 0 {
		return nil, errors.New("公钥指数非法")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: int(e.Int64())}, nil
}

// LookupPublicKey 按 kid 在 JWKS 里找公钥,支持轮换期多把公钥共存。
func LookupPublicKey(jwks JWKS, kid string) (*rsa.PublicKey, error) {
	for _, k := range jwks.Keys {
		if k.Kid == kid {
			return ParseRSAPublicKey(k)
		}
	}
	return nil, ErrUnknownKID
}

// JWKSHandler 认证中心暴露在 /.well-known/jwks.json 的端点。
func (ks *KeyStore) JWKSHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_ = json.NewEncoder(w).Encode(ks.PublicJWKS())
}

// ============================ HTTP 中间件(业务系统侧) ============================

type ctxKey struct{}

func ClaimsFrom(r *http.Request) (Claims, bool) {
	c, ok := r.Context().Value(ctxKey{}).(Claims)
	return c, ok
}

func AuthMiddleware(pub *rsa.PublicKey, opts VerifyOptions, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := r.Header.Get("Authorization")
		if !strings.HasPrefix(raw, "Bearer ") {
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}
		claims, err := Verify(strings.TrimPrefix(raw, "Bearer "), pub, opts)
		if err != nil {
			// 生产环境不要回显具体原因,这里为了演示方便
			http.Error(w, "invalid token: "+err.Error(), http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, claims)))
	})
}

// ============================ 演示 ============================

func short(s string) string {
	if len(s) > 56 {
		return s[:56] + "..."
	}
	return s
}

func title(s string) { fmt.Println("\n=== " + s + " ===") }

func testRS256() {
	// ---------- 认证中心:初始化密钥 ----------
	ks, err := NewKeyStore()
	if err != nil {
		panic(err)
	}
	title("1. 认证中心生成 RSA-2048 密钥对")
	fmt.Println("kid    :", ks.KID)
	fmt.Println("私钥   : 只在认证中心,绝不外泄(生产放 KMS/HSM)")
	fmt.Println("公钥   : 通过 JWKS 公开分发")

	// ---------- 签发 ----------
	title("2. 登录成功后签发 token")
	token, err := ks.Sign(Claims{
		"iss":   "https://sso.example.com",
		"sub":   "10086",
		"aud":   "order-service",
		"name":  "张三",
		"role":  "admin",
		"jti":   "a1b2c3d4",
		"exp":   time.Now().Add(15 * time.Minute).Unix(),
	})
	if err != nil {
		panic(err)
	}
	fmt.Println("token  :", short(token))

	// ---------- 业务系统:从 JWKS 拿公钥并验签 ----------
	title("3. 业务系统从 JWKS 端点取公钥验签")
	jwksJSON, _ := json.Marshal(ks.PublicJWKS())
	fmt.Println("jwks   :", short(string(jwksJSON)))

	// 模拟一次网络传输
	var remote JWKS
	if err := json.Unmarshal(jwksJSON, &remote); err != nil {
		panic(err)
	}
	pub, err := LookupPublicKey(remote, ks.KID)
	if err != nil {
		panic(err)
	}
	claims, err := Verify(token, pub, VerifyOptions{
		Issuer:   "https://sso.example.com",
		Audience: "order-service",
	})
	if err != nil {
		panic(err)
	}
	fmt.Println("验签通过,claims:", mustJSON(claims))

	// ---------- 攻击演示 ----------
	title("4. 篡改 payload(把 role 改成 superadmin)")
	forged := forge(token, `{"iss":"https://sso.example.com","sub":"10086","aud":"order-service","name":"张三","role":"superadmin","exp":9999999999}`)
	_, err = Verify(forged, pub, VerifyOptions{})
	fmt.Println("结果   :", err)

	title("5. alg:none 攻击(去掉签名)")
	noneTok := b64uEncode([]byte(`{"alg":"none","typ":"JWT","kid":"` + ks.KID + `"}`)) + "." +
		b64uEncode([]byte(`{"sub":"10086","role":"superadmin"}`)) + "."
	_, err = Verify(noneTok, pub, VerifyOptions{})
	fmt.Println("结果   :", err)

	title("6. 算法混淆攻击(alg 改成 HS256)")
	hsTok := b64uEncode([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." +
		b64uEncode([]byte(`{"sub":"10086","role":"superadmin"}`)) + "." + b64uEncode([]byte("fakesig"))
	_, err = Verify(hsTok, pub, VerifyOptions{})
	fmt.Println("结果   :", err)

	title("7. 过期 token")
	expired, _ := ks.Sign(Claims{"sub": "10086", "exp": time.Now().Add(-time.Minute).Unix()})
	_, err = Verify(expired, pub, VerifyOptions{})
	fmt.Println("结果   :", err)

	title("8. 结论")
	fmt.Println("私钥签发、公钥验签;验签方无法伪造 token,密钥泄露也不会导致全站沦陷。")
}

// forge 保留原签名,替换 payload 段
func forge(token, newPayload string) string {
	parts := strings.Split(token, ".")
	return parts[0] + "." + b64uEncode([]byte(newPayload)) + "." + parts[2]
}

func mustJSON(c Claims) string {
	b, _ := json.Marshal(c)
	return string(b)
}
