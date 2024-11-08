// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package socks

import (
	"net"
	"reflect"
	"testing"
)

func TestParseAuthRequest(t *testing.T) {
	for i, tt := range []struct {
		wire []byte
		req  *AuthRequest
	}{
		{
			[]byte{0x05, 0x00},
			&AuthRequest{
				Version5,
				nil,
			},
		},
		{
			[]byte{0x05, 0x01, 0xff},
			&AuthRequest{
				Version5,
				[]AuthMethod{
					AuthMethodNoAcceptableMethods,
				},
			},
		},
		{
			[]byte{0x05, 0x02, 0x00, 0xff},
			&AuthRequest{
				Version5,
				[]AuthMethod{
					AuthMethodNotRequired,
					AuthMethodNoAcceptableMethods,
				},
			},
		},

		// corrupted requests
		{nil, nil},
		{[]byte{0x00, 0x01}, nil},
		{[]byte{0x06, 0x00}, nil},
		{[]byte{0x05, 0x02, 0x00}, nil},
	} {
		req, err := ParseAuthRequest(tt.wire)
		if !reflect.DeepEqual(req, tt.req) {
			t.Errorf("#%d: got %v, %v; want %v", i, req, err, tt.req)
			continue
		}
	}
}

func TestParseCmdRequest(t *testing.T) {
	for i, tt := range []struct {
		wire []byte
		req  *CmdRequest
	}{
		{
			[]byte{0x05, 0x01, 0x00, 0x01, 192, 0, 2, 1, 0x17, 0x4b},
			&CmdRequest{
				Version5,
				CmdConnect,
				Addr{
					IP:   net.IP{192, 0, 2, 1},
					Port: 5963,
				},
			},
		},
		{
			[]byte{0x05, 0x01, 0x00, 0x03, 0x04, 'F', 'Q', 'D', 'N', 0x17, 0x4b},
			&CmdRequest{
				Version5,
				CmdConnect,
				Addr{
					Name: "FQDN",
					Port: 5963,
				},
			},
		},

		// corrupted requests
		{nil, nil},
		{[]byte{0x05}, nil},
		{[]byte{0x06, 0x01, 0x00, 0x01, 192, 0, 2, 2, 0x17, 0x4b}, nil},
		{[]byte{0x05, 0x01, 0xff, 0x01, 192, 0, 2, 3}, nil},
		{[]byte{0x05, 0x01, 0x00, 0x01, 192, 0, 2, 4}, nil},
		{[]byte{0x05, 0x01, 0x00, 0x03, 0x04, 'F', 'Q', 'D', 'N'}, nil},
	} {
		req, err := ParseCmdRequest(tt.wire)
		if !reflect.DeepEqual(req, tt.req) {
			t.Errorf("#%d: got %v, %v; want %v", i, req, err, tt.req)
			continue
		}
	}
}
