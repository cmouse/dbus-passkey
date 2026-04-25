package broker

import (
	"fmt"
	"sync"

	"github.com/cmouse/dbus-passkey/internal/types"
	"github.com/godbus/dbus/v5"
)

const requestIface = "org.freedesktop.PasskeyBroker.Request"

// Request is the D-Bus object representing an in-progress operation.
type Request struct {
	conn       *dbus.Conn
	path       dbus.ObjectPath
	sender     string // unique bus name of caller; used for disconnect-cancel matching
	cancel     chan struct{}
	cancelOnce sync.Once
	emitOnce   sync.Once
}

func newRequest(conn *dbus.Conn, path dbus.ObjectPath, sender string) *Request {
	return &Request{
		conn:   conn,
		path:   path,
		sender: sender,
		cancel: make(chan struct{}),
	}
}

// Close implements Request.Close D-Bus method. Cancels the operation.
func (r *Request) Close() *dbus.Error {
	r.cancelOp()
	return nil
}

func (r *Request) cancelOp() {
	r.cancelOnce.Do(func() {
		close(r.cancel)
	})
}

// emitResponse sends the Response signal and un-exports the object.
func (r *Request) emitResponse(code types.ResponseCode, results map[string]dbus.Variant) {
	r.emitOnce.Do(func() {
		r.conn.Export(nil, r.path, requestIface)
		r.conn.Export(nil, r.path, "org.freedesktop.DBus.Introspectable")
		_ = r.conn.Emit(r.path, requestIface+".Response", uint32(code), results)
	})
}

func (r *Request) emitSuccess(result interface{}) {
	var m map[string]dbus.Variant
	switch v := result.(type) {
	case *types.MakeCredentialResult:
		m = map[string]dbus.Variant{
			"credential_id":      dbus.MakeVariant(v.CredentialID),
			"attestation_object": dbus.MakeVariant(v.AttestationObject),
			"client_data_json":   dbus.MakeVariant(v.ClientDataJSON),
			"transports":         dbus.MakeVariant(v.Transports),
			"provider_id":        dbus.MakeVariant(v.ProviderID),
		}
	case *types.GetAssertionResult:
		m = map[string]dbus.Variant{
			"credential_id":      dbus.MakeVariant(v.CredentialID),
			"authenticator_data": dbus.MakeVariant(v.AuthenticatorData),
			"signature":          dbus.MakeVariant(v.Signature),
			"user_handle":        dbus.MakeVariant(v.UserHandle),
			"client_data_json":   dbus.MakeVariant(v.ClientDataJSON),
			"provider_id":        dbus.MakeVariant(v.ProviderID),
		}
	}
	r.emitResponse(types.ResponseSuccess, m)
}

func (r *Request) emitError(code string, msg string) {
	r.emitResponse(types.ResponseError, map[string]dbus.Variant{
		"error_code":    dbus.MakeVariant(code),
		"error_message": dbus.MakeVariant(msg),
	})
}

func (r *Request) emitCancelled() {
	r.emitResponse(types.ResponseCancelled, map[string]dbus.Variant{})
}

func (r *Request) emitInteractionEnded() {
	r.emitResponse(types.ResponseInteractionEnded, map[string]dbus.Variant{})
}

// exportRequest exports the Request object on the bus.
func exportRequest(conn *dbus.Conn, path dbus.ObjectPath, req *Request) error {
	if err := conn.Export(req, path, requestIface); err != nil {
		return fmt.Errorf("export request: %w", err)
	}
	if err := conn.Export(introspectRequest(), path, "org.freedesktop.DBus.Introspectable"); err != nil {
		return fmt.Errorf("export introspectable: %w", err)
	}
	return nil
}

type introspector struct{ xml string }

func (i introspector) Introspect() (string, *dbus.Error) { return i.xml, nil }

func introspectRequest() introspector {
	return introspector{xml: `<!DOCTYPE node PUBLIC "-//freedesktop//DTD D-BUS Object Introspection 1.0//EN"
"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd">
<node>
  <interface name="org.freedesktop.PasskeyBroker.Request">
    <method name="Close"/>
    <signal name="Response">
      <arg name="response" type="u"/>
      <arg name="results" type="a{sv}"/>
    </signal>
  </interface>
</node>`}
}
