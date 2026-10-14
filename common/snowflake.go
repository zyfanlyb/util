package common

import "github.com/bwmarrin/snowflake"


func GenerateSnowflakeId() int64 {
	node, _ := snowflake.NewNode(1)
	return node.Generate().Int64()
}