package ppk

import (
	"bufio"
	"encoding/base64"
	"io"
	"strconv"
	"strings"
)

func parseWrappedBase64(s *bufio.Scanner, countStr string) ([]byte, error) {
	count, err := strconv.Atoi(countStr)
	if err != nil {
		return nil, err
	}

	var lines []string
	for i := 0; i < count && s.Scan(); i++ {
		lines = append(lines, strings.TrimSpace(s.Text()))
	}

	if s.Err() != nil {
		return nil, s.Err()
	}
	if len(lines) < count {
		return nil, io.ErrUnexpectedEOF
	}

	value, err := base64.StdEncoding.DecodeString(strings.Join(lines, ""))
	if err != nil {
		return nil, err
	}

	return value, nil
}
