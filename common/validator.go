package common

import (
	"regexp"
	"strings"
	"unicode"
)

// ============================================================
// 手机号（中国大陆）
// ============================================================

// 纯 11 位号码：1 开头，第二位 3-9
var mobileRe = regexp.MustCompile(`^1[3-9]\d{9}$`)

// 允许带国际区号：+86 / 0086 / 86（分隔符在校验前统一剔除）
var mobileCNRe = regexp.MustCompile(`^(?:\+?86|0086)?1[3-9]\d{9}$`)

// 校验前统一剔除：空格、不换行空格(NBSP)、连字符
var mobileSep = strings.NewReplacer(" ", "", "\u00a0", "", "-", "")

// IsMobile 校验中国大陆手机号（会自动去掉首尾空格与中间分隔符）
func IsMobile(s string) bool {
	s = strings.TrimSpace(s)
	return mobileRe.MatchString(s)
}

// IsMobileCN 宽松版：接受 +86 138 0013 8000 / 0086-13800138000 等写法
func IsMobileCN(s string) bool {
	s = mobileSep.Replace(strings.TrimSpace(s))
	return mobileCNRe.MatchString(s)
}

// ============================================================
// 邮箱（实用宽松版）
// ============================================================

// 说明：
//   - 本地部分允许 字母数字 . _ % + -
//   - 域名每段只能是字母数字或连字符，且不能以连字符开头/结尾
//   - 顶级域 2-24 位字母（覆盖 .com / .info / .museum 等）
//   - 不做 RFC 5322 全量校验：那种正则有 6000+ 字符，且即便通过也说明不了邮箱存在
var emailRe = regexp.MustCompile("^[A-Za-z0-9](?:[A-Za-z0-9._%+-]{0,62}[A-Za-z0-9])?@" +
	"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\\.)+[A-Za-z]{2,24}$")

// IsEmail 校验邮箱（自动 TrimSpace，域名不区分大小写）
func IsEmail(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) > 254 { // RFC 5321 硬上限
		return false
	}
	return emailRe.MatchString(s)
}

// NormalizeEmail 归一化：去空格 + 域名转小写，便于入库去重
func NormalizeEmail(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndex(s, "@"); i > 0 {
		return s[:i] + strings.ToLower(s[i:])
	}
	return strings.ToLower(s)
}

// ============================================================
// 密码（三档强度）
// ============================================================
//
// 重要：Go 的 regexp 是 RE2，**不支持环视 (?=...) (?<=...)**，
// 所以「必须同时包含大写/小写/数字/符号」无法用一条正则写出来，
// 标准做法是：一条正则管「字符集 + 长度」，其余条件各用一条小正则判断。

type PasswordLevel int

const (
	PwdWeak   PasswordLevel = iota // 6-20 位，不含空白字符
	PwdMedium                      // 8-20 位，必须同时含 字母 + 数字
	PwdStrong                      // 8-20 位，必须同时含 大写 + 小写 + 数字 + 符号
)

var (
	pwdWeakRe   = regexp.MustCompile(`^\S{6,20}$`)
	pwdMediumRe = regexp.MustCompile(`^[A-Za-z\d]{8,20}$`)
	// 强密码字符集：可打印 ASCII（\x21-\x7e），天然排除空格、控制字符和非 ASCII 字符
	pwdStrongRe = regexp.MustCompile(`^[\x21-\x7e]{8,20}$`)

	reLower  = regexp.MustCompile(`[a-z]`)
	reUpper  = regexp.MustCompile(`[A-Z]`)
	reDigit  = regexp.MustCompile(`\d`)
	reSymbol = regexp.MustCompile(`[^A-Za-z0-9]`)

	// 弱密码黑名单：连续 4 位递增/递减、3 位重复，可选开启（用 4 位是为了减少误杀）
	reSeqAsc = regexp.MustCompile(`(?:0123|1234|2345|3456|4567|5678|6789|abcd|bcde|cdef|defg|efgh|fghi|ghij|hijk|ijkl|jklm|klmn|lmno|mnop|nopq|opqr|pqrs|qrst|rstu|stuv|tuvw|uvwx|vwxy|wxyz)`)
	reSeqDes = regexp.MustCompile(`(?:9876|8765|7654|6543|5432|4321|3210|zyxw|yxwv|xwvu|wvut|vuts|utsr|tsrq|srqp|rqpo|qpon|ponm|onml|nmlk|mlkj|lkji|kjih|jihg|ihgf|hgfe|gfed|fedc|edcb|dcba)`)
)

// hasSame3 等价于 PCRE 的 (.)\1\1：任意字符连续出现 3 次
func hasSame3(s string) bool {
	var prev rune
	n := 0
	for _, r := range s {
		if r == prev {
			n++
			if n >= 3 {
				return true
			}
			continue
		}
		prev = r
		n = 1
	}
	return false
}

// ValidatePassword 校验密码，返回 (是否通过, 失败原因)
// 失败原因可直接返回给前端做表单提示
func ValidatePassword(s string, level PasswordLevel) (bool, string) {
	switch level {
	case PwdWeak:
		if !pwdWeakRe.MatchString(s) {
			return false, "密码需为 6-20 位，且不能包含空格"
		}
	case PwdMedium:
		if !pwdMediumRe.MatchString(s) {
			return false, "密码需为 8-20 位字母或数字"
		}
		if !reLower.MatchString(s) && !reUpper.MatchString(s) {
			return false, "密码需同时包含字母和数字"
		}
		if !reDigit.MatchString(s) {
			return false, "密码需同时包含字母和数字"
		}
	case PwdStrong:
		if !pwdStrongRe.MatchString(s) {
			return false, "密码需为 8-20 位，可含字母、数字和特殊符号"
		}
		if !reLower.MatchString(s) {
			return false, "密码需包含小写字母"
		}
		if !reUpper.MatchString(s) {
			return false, "密码需包含大写字母"
		}
		if !reDigit.MatchString(s) {
			return false, "密码需包含数字"
		}
		if !reSymbol.MatchString(s) {
			return false, "密码需包含特殊符号"
		}
	}
	return true, ""
}

// IsWeakPassword 常见弱密码检测（建议在强度校验通过后叠加一层）
func IsWeakPassword(s string) bool {
	lower := strings.ToLower(s)
	return hasSame3(lower) ||
		reSeqAsc.MatchString(lower) ||
		reSeqDes.MatchString(lower)
}

// ============================================================
// 昵称（抖音口径）
// ============================================================
//
// 依据抖音开放平台《企业机构账号》规范原文：
//   「账号昵称仅支持使用中文、数字及英文，不能使用特殊符号、空格、
//     繁体字、生僻字、拆字、颜文字」
// 长度 2-20 字符，1 个汉字记 2 字符（即最多约 10 个汉字）。
//
// 注：规范里的「繁体字、生僻字、拆字」靠词表才能拦，\p{Han} 无法区分简繁，
// 需要的话另接敏感词/简繁转换库处理，这里不做。

var (
	// 字符集白名单：中文 + 英文字母 + 数字
	// 这一条已经顺带挡掉了空格、emoji、标点、全角符号，无需再单独检测 emoji
	// 若你的场景要放开下划线/减号，改成 `^[\p{Han}A-Za-z0-9_-]+$`
	nicknameRe = regexp.MustCompile(`^[\p{Han}A-Za-z0-9]+$`)

	// 不可见字符：\p{Cc} 控制字符 + \p{Cf} 格式字符
	// 覆盖 U+200B 零宽空格、U+202A-U+202E 双向覆写、U+FEFF BOM、U+00AD 软连字符
	// 抖音明确禁「不可见空格」；更要命的是它能让 "张三" 与 "张三<U+200B>"
	// 绕过昵称唯一性校验，所以单独拦截而不是静默剔除
	reInvisible = regexp.MustCompile(`[\p{Cc}\p{Cf}]`)

	// 纯数字，抖音同样拒绝
	// 写在字符集白名单之后，此时只剩 ASCII 数字，用 \d 即可
	reDigitOnly = regexp.MustCompile(`^\d+$`)

	// 敏感词库：生产环境请换成 DFA/Trie（Aho-Corasick），词库上千条时线性遍历太慢
	// 留空则跳过该项检查
	SensitiveWords []string
)

const (
	nicknameMinWidth = 2  // 最短 2 字符
	nicknameMaxWidth = 20 // 最长 20 字符（汉字记 2，约 10 个汉字）
)

// NicknameWidth 显示宽度：CJK 记 2，其余记 1
// 抖音按此口径算长度，所以「最多 20 字符」指的是宽度 20 而非 20 个 rune
func NicknameWidth(s string) int {
	w := 0
	for _, r := range s {
		if unicode.Is(unicode.Han, r) {
			w += 2
		} else {
			w++
		}
	}
	return w
}

// ValidateNickname 校验昵称，返回 (是否通过, 失败原因)
// 失败原因可直接返给前端做表单提示
func ValidateNickname(s string) (bool, string) {
	s = strings.TrimSpace(s)

	// 1. 不可见字符
	if reInvisible.MatchString(s) {
		return false, "昵称不能包含不可见字符"
	}

	// 2. 字符集：中文、英文、数字
	if !nicknameRe.MatchString(s) {
		return false, "昵称仅支持中文、英文和数字"
	}

	// 3. 长度（汉字记 2）
	w := NicknameWidth(s)
	if w < nicknameMinWidth {
		return false, "昵称至少 2 个字符"
	}
	if w > nicknameMaxWidth {
		return false, "昵称最多 20 个字符（约 10 个汉字）"
	}

	// 4. 纯数字
	if reDigitOnly.MatchString(s) {
		return false, "昵称不能是纯数字"
	}

	// 5. 敏感词
	lower := strings.ToLower(s)
	for _, w := range SensitiveWords {
		if w != "" && strings.Contains(lower, strings.ToLower(w)) {
			return false, "昵称包含违规内容"
		}
	}

	return true, ""
}