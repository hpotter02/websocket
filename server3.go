package websocket

import (
	"bufio"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"math"
	"net/http"
	"strconv"
	"time"
	"unicode"
	"unicode/utf8"
)

//Upgrade0 ...
func (u *Upgrader) Upgrade0(w http.ResponseWriter, r *http.Request, responseHeader http.Header) (*Conn, error) {
	fmt.Println("ws3")
	const badHandshake = "websocket: the client is not using the websocket protocol: "

	if !tokenListContainsValue(r.Header, "Connection", "upgrade") {
		return u.returnError(w, r, http.StatusBadRequest, badHandshake+"'upgrade' token not found in 'Connection' header")
	}

	if !tokenListContainsValue(r.Header, "Upgrade", "websocket") {
		return u.returnError(w, r, http.StatusBadRequest, badHandshake+"'websocket' token not found in 'Upgrade' header")
	}

	if r.Method != "GET" {
		return u.returnError(w, r, http.StatusMethodNotAllowed, badHandshake+"request method is not GET")
	}

	checkOrigin := u.CheckOrigin
	if checkOrigin == nil {
		checkOrigin = checkSameOrigin
	}
	if !checkOrigin(r) {
		return u.returnError(w, r, http.StatusForbidden, "websocket: request origin not allowed by Upgrader.CheckOrigin")
	}

	key1 := r.Header.Get("Sec-Websocket-Key1")
	if key1 == "" {
		return u.returnError(w, r, http.StatusBadRequest, "websocket: not a websocket handshake: 'Sec-WebSocket-Key1' header is missing or blank")
	}

	key2 := r.Header.Get("Sec-Websocket-Key2")
	if key2 == "" {
		return u.returnError(w, r, http.StatusBadRequest, "websocket: not a websocket handshake: 'Sec-WebSocket-Key2' header is missing or blank")
	}

	subprotocol := u.selectSubprotocol(r, responseHeader)

	// Negotiate PMCE
	var compress bool
	if u.EnableCompression {
		for _, ext := range parseExtensions(r.Header) {
			if ext[""] != "permessage-deflate" {
				continue
			}
			compress = true
			break
		}
	}

	h, ok := w.(http.Hijacker)
	if !ok {
		return u.returnError(w, r, http.StatusInternalServerError, "websocket: response does not implement http.Hijacker")
	}
	var brw *bufio.ReadWriter
	netConn, brw, err := h.Hijack()
	if err != nil {
		return u.returnError(w, r, http.StatusInternalServerError, err.Error())
	}

	zy, _ := brw.Peek(8)
	fmt.Println(zy)
	fmt.Println(brw.Reader.Buffered())
	xyz, _ := ioutil.ReadAll(r.Body)
	fmt.Printf("%x\n", xyz)

	if brw.Reader.Buffered() < 8 {
		return u.returnError(w, r, http.StatusInternalServerError, "socket sent to few bytes")
	}
	key3 := make([]byte, 8)
	for i := 0; i < 8; i++ {
		key3[i], _ = brw.ReadByte()
		fmt.Printf("%x", key3[i])
	}
	key := append(ComputeAcceptKey0(key1, key2), key3...)
	hs := md5.New()
	hs.Write(key)
	md5sum := hs.Sum(nil)
	fmt.Printf("md5: %x\n", md5sum)
	fmt.Printf("key: %x\n", key)
	var br *bufio.Reader
	if u.ReadBufferSize == 0 && bufioReaderSize(netConn, brw.Reader) > 256 {
		// Reuse hijacked buffered reader as connection reader.
		br = brw.Reader
	}

	buf := bufioWriterBuffer(netConn, brw.Writer)

	var writeBuf []byte
	if u.WriteBufferPool == nil && u.WriteBufferSize == 0 && len(buf) >= maxFrameHeaderSize+256 {
		// Reuse hijacked write buffer as connection buffer.
		writeBuf = buf
	}

	c := newConn(netConn, true, u.ReadBufferSize, u.WriteBufferSize, u.WriteBufferPool, br, writeBuf)
	c.subprotocol = subprotocol

	if compress {
		c.newCompressionWriter = compressNoContextTakeover
		c.newDecompressionReader = decompressNoContextTakeover
	}

	// Use larger of hijacked buffer and connection write buffer for header.
	p := buf
	if len(c.writeBuf) > len(p) {
		p = c.writeBuf
	}
	p = p[:0]

	p = append(p, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: WebSocket\r\nConnection: Upgrade\r\n"...)
	//p = append(p, "Sec-WebSocket-Location: "+strings.Replace(r.Header.Get("Origin")+"\r\n", "http", "ws", 1)...)
	p = append(p, "Sec-WebSocket-Location: ws://192.168.1.100:8040/socket?device=kindle\r\n"...)
	p = append(p, "Sec-WebSocket-Origin: "+r.Header.Get("Origin")+"\r\n"...)
	if c.subprotocol != "" {
		p = append(p, "Sec-WebSocket-Protocol: "...)
		p = append(p, c.subprotocol...)
		p = append(p, "\r\n"...)
	}
	if compress {
		p = append(p, "Sec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover; client_no_context_takeover\r\n"...)
	}
	for k, vs := range responseHeader {
		if k == "Sec-Websocket-Protocol" {
			continue
		}
		for _, v := range vs {
			p = append(p, k...)
			p = append(p, ": "...)
			for i := 0; i < len(v); i++ {
				b := v[i]
				if b <= 31 {
					// prevent response splitting.
					b = ' '
				}
				p = append(p, b)
			}
			p = append(p, "\r\n"...)
		}
	}
	p = append(p, "\r\n"...)
	p = append(p, hs.Sum(nil)...)

	// Clear deadlines set by HTTP server.
	netConn.SetDeadline(time.Time{})

	if u.HandshakeTimeout > 0 {
		netConn.SetWriteDeadline(time.Now().Add(u.HandshakeTimeout))
	}
	if _, err = netConn.Write(p); err != nil {
		netConn.Close()
		return nil, err
	}
	if u.HandshakeTimeout > 0 {
		netConn.SetWriteDeadline(time.Time{})
	}
	c.isHyBi0 = true
	return c, nil
}

//ComputeAcceptKey0 ...
func ComputeAcceptKey0(key1 string, key2 string) []byte {
	num1, spaces1 := parseKey(key1)
	fmt.Printf("num1: %d\n", num1)
	num2, spaces2 := parseKey(key2)
	fmt.Printf("num2: %d\n", num2)
	part1 := num1 / spaces1
	fmt.Printf("part1: %d\n", part1)
	part2 := num2 / spaces2
	fmt.Printf("part2: %d\n", part2)
	if part1 == part2 {
		fmt.Println("wtf")
	}
	var out1 []byte
	out1 = make([]byte, 4)
	binary.BigEndian.PutUint32(out1, uint32(part1))
	var out2 []byte
	out2 = make([]byte, 4)
	binary.BigEndian.PutUint32(out2, uint32(part2))
	return append(out1, out2...)

}

func parseKey(key string) (int, int) {
	var spaces int
	var num int
	pow := 9
	for _, v := range key {
		if string(v) == " " {
			spaces++
		}
		if unicode.IsDigit(v) {
			buf := make([]byte, 1)
			_ = utf8.EncodeRune(buf, v)
			n, _ := strconv.Atoi(string(buf))
			num += (n * int(math.Pow(10, float64(pow))))
			pow--
		}
	}
	return num, spaces
}

//Upgrade0 ...
func Upgrade0(w http.ResponseWriter, r *http.Request, responseHeader http.Header, readBufSize, writeBufSize int) (*Conn, error) {
	u := Upgrader{ReadBufferSize: readBufSize, WriteBufferSize: writeBufSize}
	u.Error = func(w http.ResponseWriter, r *http.Request, status int, reason error) {
		// don't return errors to maintain backwards compatibility
	}
	u.CheckOrigin = func(r *http.Request) bool {
		// allow all connections by default
		return true
	}
	return u.Upgrade0(w, r, responseHeader)
}
