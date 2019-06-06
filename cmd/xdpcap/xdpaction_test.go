package main

import (
	"testing"
)

func TestActionParsing(t *testing.T) {
	// We can't parse unknownAction.String(), this checks all actions in xdpAction have a "real" string mapping
	for _, action := range xdpActions {
		parsed, err := parseAction(action.String())
		if err != nil {
			t.Fatal(err)
		}

		if parsed != action {
			t.Fatalf("Expected %v, got %v", action, parsed)
		}
	}
}

func TestNegativeAction(t *testing.T) {
	_, err := parseAction("-3")
	if err == nil {
		t.Fatal("negative action parsed")
	}
}

func TestUnknownActionParsing(t *testing.T) {
	action, err := parseAction("1234")
	if err != nil {
		t.Fatal(err)
	}
	if action != xdpAction(1234) {
		t.Fatalf("unexpected action")
	}

	action, err = parseAction("0xDEADBEEF")
	if err != nil {
		t.Fatal(err)
	}
	if action != xdpAction(0xDEADBEEF) {
		t.Fatalf("unexpected action")
	}
}
