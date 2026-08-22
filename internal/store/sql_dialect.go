package store

import (
	"strconv"
	"strings"
)

type sqlDialect string

const (
	dialectSQLite     sqlDialect = "sqlite"
	dialectPostgreSQL sqlDialect = "postgresql"
)

func bindQuery(dialect sqlDialect, query string) string {
	if dialect != dialectPostgreSQL {
		return query
	}
	var output strings.Builder
	output.Grow(len(query))
	placeholder := 1
	quote := byte(0)
	for index := 0; index < len(query); index++ {
		character := query[index]
		if quote != 0 {
			output.WriteByte(character)
			if character != quote {
				continue
			}
			if index+1 < len(query) && query[index+1] == quote {
				index++
				output.WriteByte(quote)
				continue
			}
			quote = 0
			continue
		}
		if character == '\'' || character == '"' {
			quote = character
			output.WriteByte(character)
			continue
		}
		if character != '?' {
			output.WriteByte(character)
			continue
		}
		output.WriteByte('$')
		output.WriteString(strconv.Itoa(placeholder))
		placeholder++
	}
	return output.String()
}
