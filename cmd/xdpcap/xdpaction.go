package main

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

type xdpAction int

const (
	xdpAborted xdpAction = iota
	xdpDrop
	xdpPass
	xdpTx
)

func (a xdpAction) String() string {
	switch a {
	case xdpAborted:
		return "aborted"
	case xdpDrop:
		return "drop"
	case xdpPass:
		return "pass"
	case xdpTx:
		return "tx"
	default:
		return fmt.Sprintf("xdpAction(%d)", a)
	}
}

func parseAction(action string) (xdpAction, error) {
	a := strings.TrimSpace(strings.ToLower(action))

	switch a {
	case "aborted":
		return xdpAborted, nil
	case "drop":
		return xdpDrop, nil
	case "pass":
		return xdpPass, nil
	case "tx":
		return xdpTx, nil
	default:
		// Accept actions we don't know about using their numeric value
		unknownAction, err := strconv.Atoi(a)
		if err != nil {
			return 0, errors.Errorf("unknown action %s", action)
		}

		return xdpAction(unknownAction), nil
	}
}
