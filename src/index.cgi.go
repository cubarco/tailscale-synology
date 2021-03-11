package main

import (
	"fmt"
	"os"
	"os/exec"
	"net/http"
	"net/http/cgi"
	"encoding/json"
	"bytes"
	"log"
	"strings"
)

func main() {
	if err := cgi.Serve(http.HandlerFunc(cgiHandler)); err != nil {
		log.Fatal(err)
	}
}

func cgiHandler(w http.ResponseWriter, r *http.Request) {
	if synoTokenRedirect(w, r) {
		return
	}

	user, err := auth()
	if err != nil {
		http.Error(w, err.Error(), 403)
		log.Fatal("tag 1: %v", err.Error())
		return
	}

	s, err := tailscaleStatus()
	if err != nil {
		http.Error(w, err.Error(), 500)
		log.Fatal("tag 2: %v", err.Error())
		return
	}
	if uid := os.Getuid() ; uid != 0 {
		http.Error(w, fmt.Sprintf("cgi running as %d, not root", uid), 500)
		return
	}

	buf := new(bytes.Buffer)
	wr := func(format string, args ...interface{}) {
		for i, arg := range args {
			v := fmt.Sprintf("%v", arg)
			v = strings.Replace(v, "&", "&amp;", -1)
			args[i] = strings.Replace(v, "<", "&lt;", -1)
		}
		fmt.Fprintf(buf, format+"\n", args...)
	}
	wr("<!doctype html>")
	wr("<html><title>Tailscale Synology App</title><body>")
	wr("<h1>Tailscale</h1>")
	wr(`<div style="float:right;">%s</div>`, user)
	wr("<table>")
	wr("<tr><th>Status:</th><td>%s</td></tr>", s.BackendState)
	wr("<tr><th>Device Name:</th><td>%s</td></tr>", s.Self.DNSName)
	wr("<tr><th>Tailscale IPs:</th><td>")
	for i, ip := range s.TailscaleIPs {
		if i > 0 {
			wr(", ")
		}
		wr("%s", ip)
	}
	wr("</td></tr>")
	wr("</table>")

	wr(`<form method="POST">`)
	wr(`<p><input type="submit" value="Log in…"></p>`)
	wr(`</form>`)
	url := s.AuthURL
	if r.FormValue("action") == "login" {
		_, url, err = tailscaleUp()
		if err != nil {
			wr(`<p style="color: red; font-weight: bold;">%v</p>`, err)
		}
		if url != "" {
			s.AuthURL = url
		}
	}
	if s.BackendState != "Running" && url != "" {
		wr(`<p><b>To authorize this device visit: <a href=%q>%s</a></b></p>`, url, url)
	}

	wr("</body></html>")

	w.Write(buf.Bytes())
}

type status struct {
	BackendState string
	AuthURL string
	TailscaleIPs []string
	Self struct {
		DNSName string
	}
}

func tailscaleStatus() (*status, error) {
	cmd := exec.Command("tailscale", "status", "-json")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("tailscaleStatus: %v: %s", err, out)
	}
	s := new(status)
	if err := json.Unmarshal(out, s); err != nil {
		return nil, fmt.Errorf("tailscaleStatus: %v", err)
	}
	return s,nil
}

func tailscaleUp() (state, url string, err error) {
	cmd := exec.Command("tailscale", "up", "-json")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", "", fmt.Errorf("tailscaleUp: %v: %s", err, out)
	}
	var res struct {
		State string `json:"state"`
		AuthURL string `json:"auth_url"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(out, &res); err != nil {
		return "", "", fmt.Errorf("tailscaleUp: %v", err)
	}
	if res.Error != "" {
		return "", "", fmt.Errorf("tailscaleUp: %s", res.Error)
	}
	return res.State, res.AuthURL, nil
}

func auth() (string, error) {
	cmd := exec.Command("/usr/syno/synoman/webman/modules/authenticate.cgi")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("auth: %v: %s", err, out)
	}
	return string(out), nil
}

func synoTokenRedirect(w http.ResponseWriter, r *http.Request) bool {
	if r.Header.Get("X-Syno-Token") != "" {
		return false
	}
	if r.URL.Query().Get("SynoToken") != "" {
		return false
	}
	if r.Method == "POST" && r.FormValue("SynoToken") != "" {
		return false
	}
	// We need a SynoToken for authenticate.cgi.
	// So we tell the client to get one.
	serverURL := r.URL.Scheme + "://" + r.URL.Host
	fmt.Fprintf(w, synoTokenRedirectHTML, serverURL)
	return true
}

const synoTokenRedirectHTML = `<html><body>
Redirecting with session token...
<script>
var serverURL = %q;
var req = new XMLHttpRequest();
req.overrideMimeType("application/json");
req.open("GET", serverURL + "/webman/login.cgi", true);
req.onload = function() {
	var jsonResponse = JSON.parse(req.responseText);
	var token = jsonResponse["SynoToken"];
	document.location.href = serverURL + "/webman/3rdparty/Tailscale/?SynoToken=" + token;
};
req.send(null);
</script>
</body></html>
`
