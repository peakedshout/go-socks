package share

import (
	"fmt"
	"net"
	"sync"
)

type ConnMap struct {
	connLock   sync.Mutex
	connMap    map[string]net.Conn
	disableSet bool
}

func NewConnMap() *ConnMap {
	return &ConnMap{
		connLock: sync.Mutex{},
		connMap:  make(map[string]net.Conn),
	}
}
func (cm *ConnMap) Disable() {
	cm.connLock.Lock()
	defer cm.connLock.Unlock()
	cm.disableSet = true
}
func (cm *ConnMap) SetConn(conn net.Conn) bool {
	cm.connLock.Lock()
	defer cm.connLock.Unlock()
	if cm.disableSet {
		return false
	}
	cm.connMap[cm.getConnId2(conn.RemoteAddr())] = conn
	return true
}
func (cm *ConnMap) SetConn2(addr net.Addr, conn net.Conn) bool {
	cm.connLock.Lock()
	defer cm.connLock.Unlock()
	if cm.disableSet {
		return false
	}
	cm.connMap[cm.getConnId2(addr)] = conn
	return true
}
func (cm *ConnMap) DelConn(addr net.Addr) {
	cm.connLock.Lock()
	defer cm.connLock.Unlock()
	if addr == nil {
		return
	}
	delete(cm.connMap, cm.getConnId2(addr))
}
func (cm *ConnMap) GetConn(addr net.Addr) net.Conn {
	cm.connLock.Lock()
	defer cm.connLock.Unlock()
	if addr == nil {
		return nil
	}
	return cm.connMap[cm.getConnId2(addr)]
}
func (cm *ConnMap) GetConn2(addr net.Addr) (net.Conn, bool) {
	cm.connLock.Lock()
	defer cm.connLock.Unlock()
	if addr == nil {
		return nil, false
	}
	conn, ok := cm.connMap[cm.getConnId2(addr)]
	return conn, ok
}
func (cm *ConnMap) GetAndDelConn(addr net.Addr) net.Conn {
	cm.connLock.Lock()
	defer cm.connLock.Unlock()
	if addr == nil {
		return nil
	}
	id := cm.getConnId2(addr)
	conn := cm.connMap[id]
	delete(cm.connMap, id)
	return conn
}
func (cm *ConnMap) GetAndDelConn2(addr net.Addr) (net.Conn, bool) {
	cm.connLock.Lock()
	defer cm.connLock.Unlock()
	if addr == nil {
		return nil, false
	}
	id := cm.getConnId2(addr)
	conn, ok := cm.connMap[id]
	if !ok {
		return nil, ok
	}
	delete(cm.connMap, id)
	return conn, ok
}
func (cm *ConnMap) RangeConn(fn func(conn net.Conn) bool) {
	cm.connLock.Lock()
	defer cm.connLock.Unlock()
	for _, one := range cm.connMap {
		if !fn(one) {
			return
		}
	}
}
func (cm *ConnMap) Clear() {
	cm.connLock.Lock()
	defer cm.connLock.Unlock()
	cm.connMap = make(map[string]net.Conn)
}

func (cm *ConnMap) getConnId(network, addr string) string {
	return fmt.Sprintf("%s://%s", network, addr)
}
func (cm *ConnMap) getConnId2(addr net.Addr) string {
	return cm.getConnId(addr.Network(), addr.String())
}
