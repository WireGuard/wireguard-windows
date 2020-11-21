/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2020 WireGuard LLC. All Rights Reserved.
 */

package tunnel_test

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"golang.zx2c4.com/wireguard/tun"

	"golang.zx2c4.com/wireguard/windows/elevate"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

func TestWintunOrdering(t *testing.T) {
	var tunDevice tun.Device
	err := elevate.DoAsSystem(func() error {
		var err error
		tunDevice, err = tun.CreateTUNWithRequestedGUID("tunordertest", &windows.GUID{12, 12, 12, [8]byte{12, 12, 12, 12, 12, 12, 12, 12}}, 1500)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tunDevice.Close()
	nativeTunDevice := tunDevice.(*tun.NativeTun)
	luid := winipcfg.LUID(nativeTunDevice.LUID())
	ip, ipnet, _ := net.ParseCIDR("10.82.31.4/24")
	err = luid.SetIPAddresses([]net.IPNet{{ip, ipnet.Mask}})
	if err != nil {
		t.Fatal(err)
	}
	err = luid.SetRoutes([]*winipcfg.RouteData{{*ipnet, ipnet.IP, 0}})
	if err != nil {
		t.Fatal(err)
	}
	var token [32]byte
	_, err = rand.Read(token[:])
	if err != nil {
		t.Fatal(err)
	}
	var sockWrite net.Conn
	for i := 0; i < 1000; i++ {
		sockWrite, err = net.Dial("udp", "10.82.31.5:9999")
		if err == nil {
			defer sockWrite.Close()
			break
		}
		time.Sleep(time.Millisecond * 100)
	}
	if err != nil {
		t.Fatal(err)
	}
	var sockRead *net.UDPConn
	for i := 0; i < 1000; i++ {
		var listenAddress *net.UDPAddr
		listenAddress, err = net.ResolveUDPAddr("udp", "10.82.31.4:9999")
		if err != nil {
			continue
		}
		sockRead, err = net.ListenUDP("udp", listenAddress)
		if err == nil {
			defer sockRead.Close()
			break
		}
		time.Sleep(time.Millisecond * 100)
	}
	if err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	wait.Add(4)
	doneSockWrite := false
	doneTunWrite := false
	fatalErrors := make(chan error, 2)
	errors := make(chan error, 2)
	go func() {
		defer wait.Done()
		buffer := append(token[:], 0, 0, 0, 0, 0, 0, 0, 0)
		for sendingIndex := uint64(0); !doneSockWrite; sendingIndex++ {
			binary.LittleEndian.PutUint64(buffer[32:], sendingIndex)
			_, err := sockWrite.Write(buffer[:])
			if err != nil {
				fatalErrors <- err
			}
		}
	}()
	go func() {
		defer wait.Done()
		packet := [20 + 8 + 32 + 8]byte{
			0x45, 0, 0, 20 + 8 + 32 + 8,
			0, 0, 0, 0,
			0x80, 0x11, 0, 0,
			10, 82, 31, 5,
			10, 82, 31, 4,
			8888 >> 8, 8888 & 0xff, 9999 >> 8, 9999 & 0xff, 0, 8 + 32 + 8, 0, 0,
		}
		copy(packet[28:], token[:])
		for sendingIndex := uint64(0); !doneTunWrite; sendingIndex++ {
			binary.BigEndian.PutUint16(packet[4:], uint16(sendingIndex))
			var checksum uint32
			for i := 0; i < 20; i += 2 {
				if i != 10 {
					checksum += uint32(binary.BigEndian.Uint16(packet[i:]))
				}
			}
			binary.BigEndian.PutUint16(packet[10:], ^(uint16(checksum>>16) + uint16(checksum&0xffff)))
			binary.LittleEndian.PutUint64(packet[20+8+32:], sendingIndex)
			n, err := tunDevice.Write(packet[:], 0)
			if err != nil {
				fatalErrors <- err
			}
			if n == 0 {
				time.Sleep(time.Millisecond * 300)
			}
		}
	}()
	const packetsPerTest = 1 << 21
	go func() {
		defer func() {
			doneSockWrite = true
			wait.Done()
		}()
		var expectedIndex uint64
		for i := uint64(0); i < packetsPerTest; {
			var buffer [(1 << 16) - 1]byte
			bytesRead, err := tunDevice.Read(buffer[:], 0)
			if err != nil {
				fatalErrors <- err
			}
			if bytesRead < 0 || bytesRead > len(buffer) {
				continue
			}
			packet := buffer[:bytesRead]
			tokenPos := bytes.Index(packet, token[:])
			if tokenPos == -1 || tokenPos+32+8 > len(packet) {
				continue
			}
			foundIndex := binary.LittleEndian.Uint64(packet[tokenPos+32:])
			if foundIndex < expectedIndex {
				errors <- fmt.Errorf("Sock write, tun read: expected packet %d, received packet %d", expectedIndex, foundIndex)
			}
			expectedIndex = foundIndex + 1
			i++
		}
	}()
	go func() {
		defer func() {
			doneTunWrite = true
			wait.Done()
		}()
		var expectedIndex uint64
		for i := uint64(0); i < packetsPerTest; {
			var buffer [(1 << 16) - 1]byte
			bytesRead, err := sockRead.Read(buffer[:])
			if err != nil {
				fatalErrors <- err
			}
			if bytesRead < 0 || bytesRead > len(buffer) {
				continue
			}
			packet := buffer[:bytesRead]
			if len(packet) != 32+8 || !bytes.HasPrefix(packet, token[:]) {
				continue
			}
			foundIndex := binary.LittleEndian.Uint64(packet[32:])
			if foundIndex < expectedIndex {
				errors <- fmt.Errorf("Tun write, sock read: expected packet %d, received packet %d", expectedIndex, foundIndex)
			}
			expectedIndex = foundIndex + 1
			i++
		}
	}()
	done := make(chan bool, 2)
	doneFunc := func() {
		wait.Wait()
		done <- true
	}
	defer doneFunc()
	go doneFunc()
	for {
		select {
		case err := <-fatalErrors:
			t.Fatal(err)
		case err := <-errors:
			t.Error(err)
		case <-done:
			return
		}
	}
}
