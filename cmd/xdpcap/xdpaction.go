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
	xdpRedirect
)

// All known XDP actions
var xdpActions = []xdpAction{
	xdpAborted,
	xdpDrop,
	xdpPass,
	xdpTx,
	xdpRedirect,
}

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
	case xdpRedirect:
		return "redirect"
	default:
		return fmt.Sprintf("xdpAction(%d)", a)
	}
}

func parseAction(action string) (xdpAction, error) {
	a := strings.TrimSpace(strings.ToLower(action))

	for _, act := range xdpActions {
		if a == act.String() {
			return act, nil
		}
	}

	// Accept actions we don't know about using their numeric value
	// Base 0 to accept hex 0x values
	unknownAction, err := strconv.ParseUint(a, 0, 0)
	if err != nil {
		return 0, errors.Errorf("unknown action %s", action)
	}

	return xdpAction(unknownAction), nil
}
