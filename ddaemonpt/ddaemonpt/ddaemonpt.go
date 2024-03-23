package ddaemonpt

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"fwx001/ddaemonpt/internal/log"
	"fwx001/ddaemonpt/internal/middleware"
)

const (
	minTlsVersion = tls.VersionTLS12
)

