// Package ginlogr provides log handling using logr package.
// Code structure based on ginrus package.
package ginlogr

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"runtime/debug"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-logr/logr"
	"github.com/pkg/errors"
)

type stackTracer interface {
	StackTrace() errors.StackTrace
}

// Ginlogr returns a gin.HandlerFunc (middleware) that logs requests using github.com/go-logr/logr.
//
// Requests with errors are logged using logr.Error().
// Requests without errors are logged using logr.Info().
//
// It receives:
//  1. A time package format string (e.g. time.RFC3339).
//  2. A boolean stating whether to use UTC time zone or local.
func Ginlogr(logger logr.Logger, timeFormat string, utc, addToReqContext bool, withHeaders []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		// some evil middlewares modify this values
		path := c.Request.URL.Path
		query := c.Request.URL.RawQuery
		reqLogger := logger
		for _, headerKey := range withHeaders {
			reqLogger = reqLogger.WithValues(headerKey, c.Writer.Header().Get(headerKey))
		}
		if addToReqContext {
			*c = logr.NewContext(*c, reqLogger)
			c.Request = c.Request.Clone(logr.NewContext(c.Request.Context(), reqLogger))
		}
		c.Next()

		end := time.Now()
		latency := end.Sub(start).Microseconds()
		if utc {
			end = end.UTC()
		}

		if len(c.Errors) > 0 {
			// Append error field if this is an erroneous request.
			for _, e := range c.Errors {
				reqLogger.Error(e.Err, "Error")
			}
		}
		reqLogger.Info(path,
			"status", c.Writer.Status(),
			"method", c.Request.Method,
			"path", path,
			"query", query,
			"ip", c.ClientIP(),
			"user-agent", c.Request.UserAgent(),
			"time", end.Format(timeFormat),
			"latency", latency,
			"logger", "ginlogr",
		)
	}
}

// RecoveryWithlogr returns a gin.HandlerFunc (middleware)
// that recovers from any panics and logs requests using uber-go/logr.
// All errors are logged using logr.Error().
// stack means whether output the stack info.
// The stack info is easy to find where the error occurs but the stack info is too large.
func RecoveryWithLogr(logger logr.Logger, timeFormat string, utc, stack bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				time := time.Now()
				if utc {
					time = time.UTC()
				}

				reqLogger := logger
				if lgr, err := logr.FromContext(c); err == nil {
					reqLogger = lgr
				}

				// Check for a broken connection, as it is not really a
				// condition that warrants a panic stack trace.
				var brokenPipe bool
				if ne, ok := err.(*net.OpError); ok {
					if se, ok := ne.Err.(*os.SyscallError); ok {
						if strings.Contains(strings.ToLower(se.Error()), "broken pipe") ||
							strings.Contains(strings.ToLower(se.Error()), "connection reset by peer") {
							brokenPipe = true
						}
					}
				}

				httpRequest, _ := httputil.DumpRequest(c.Request, false)

				e, ok := err.(error)
				if !ok {
					e = fmt.Errorf("%v", err)
				}

				switch {
				case brokenPipe:
					reqLogger.Error(err.(*os.SyscallError), c.Request.URL.Path,
						"time", time.Format(timeFormat),
						"request", string(httpRequest),
					)
					// If the connection is dead, we can't write a status to it.
					c.Error(e) // nolint: errcheck
					c.Abort()
					return
				case stack:
					var stackErr stackTracer
					var stackTrace []string
					if stackErr, ok = e.(stackTracer); ok {
						stackTrace = make([]string, len(stackErr.StackTrace()))
						for i, f := range stackErr.StackTrace() {
							stackTrace[i] = fmt.Sprintf("%+s:%d\n", f, f)
						}
					} else {
						stackTrace = strings.Split("\n", strings.ReplaceAll(string(debug.Stack()), "\t", ""))
					}

					reqLogger.Error(e, "[Recovery from panic]",
						"time", time.Format(timeFormat),
						"request", string(httpRequest),
						"stack", stackTrace,
					)
				default:
					reqLogger.Error(e, "[Recovery from panic]",
						"time", time.Format(timeFormat),
						"request", string(httpRequest),
					)
				}

				c.AbortWithStatus(http.StatusInternalServerError)
			}
		}()
		c.Next()
	}
}

// Storing and retrieving Loggers with logr relies on using a context.Context, while Gin uses
// gin.Context. We'll reimplement that functionality here

// contextKey is how we find Loggers in a context.Context.
const contextKey string = "__ginlogr__context__key"

// FromContext returns a Logger from ctx or an error if no Logger is found.
func FromContext(ctx *gin.Context) (logr.Logger, error) {
	if v, ok := ctx.Value(contextKey).(logr.Logger); ok {
		return v, nil
	}

	return logr.Logger{}, notFoundError{}
}

// notFoundError exists to carry an IsNotFound method.
type notFoundError struct{}

func (notFoundError) Error() string {
	return "no logr.Logger was present"
}

func (notFoundError) IsNotFound() bool {
	return true
}

// FromContextOrDiscard returns a Logger from ctx.  If no Logger is found, this
// returns a Logger that discards all log messages.
func FromContextOrDiscard(ctx context.Context) Logger {
	if v, ok := ctx.Value(contextKey{}).(Logger); ok {
		return v
	}

	return Discard()
}

// NewContext returns a new Context, derived from ctx, which carries the
// provided Logger.
func NewContext(ctx context.Context, logger Logger) context.Context {
	return context.WithValue(ctx, contextKey{}, logger)
}
