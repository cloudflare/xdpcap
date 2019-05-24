package main

type xdpAction int

//go:generate stringer -type=xdpAction -trimprefix=xdp

const (
	xdpAborted xdpAction = iota
	xdpDrop
	xdpPass
	xdpTx
)
