package domainconnect

import "errors"

var (
	ErrNoDomainConnectRecord   = errors.New("no _domainconnect TXT record")
	ErrNoDomainConnectSettings = errors.New("no domain connect settings")
	ErrInvalidSettings         = errors.New("invalid domain connect settings")
	ErrTemplateNotSupported    = errors.New("template not supported")
	ErrConflictOnApply         = errors.New("conflict on apply")
	ErrApply                   = errors.New("apply error")
	ErrAsyncToken              = errors.New("async token error")
)
