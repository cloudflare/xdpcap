package main

type XDPAction int

//go:generate stringer -type=XDPAction

const (
	XDPAborted XDPAction = iota
	XDPDrop
	XDPPass
	XDPTx
)
