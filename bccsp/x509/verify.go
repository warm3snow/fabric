package x509

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"time"
)

type VerifyOptions struct {
	DNSName       string
	Intermediates *CertPool
	Roots         *CertPool // if nil, the system roots are used
	CurrentTime   time.Time // if zero, the current time is used
	// KeyUsage specifies which Extended Key Usage values are acceptable.
	// An empty list means ExtKeyUsageServerAuth. Key usage is considered a
	// constraint down the chain which mirrors Windows CryptoAPI behavior,
	// but not the spec. To accept any key usage, include ExtKeyUsageAny.
	KeyUsages []x509.ExtKeyUsage
}

const (
	leafCertificate = iota
	intermediateCertificate
	rootCertificate
)

type InvalidReason int

const (
	// NotAuthorizedToSign results when a certificate is signed by another
	// which isn't marked as a CA certificate.
	NotAuthorizedToSign InvalidReason = iota
	// Expired results when a certificate has expired, based on the time
	// given in the VerifyOptions.
	Expired
	// CANotAuthorizedForThisName results when an intermediate or root
	// certificate has a name constraint which doesn't include the name
	// being checked.
	CANotAuthorizedForThisName
	// TooManyIntermediates results when a path length constraint is
	// violated.
	TooManyIntermediates
	// IncompatibleUsage results when the certificate's key usage indicates
	// that it may only be used for a different purpose.
	IncompatibleUsage
	// NameMismatch results when the subject name of a parent certificate
	// does not match the issuer name in the child.
	NameMismatch
)

type CertificateInvalidError struct {
	Cert   *x509.Certificate
	Reason InvalidReason
}

func (e CertificateInvalidError) Error() string {
	switch e.Reason {
	case NotAuthorizedToSign:
		return "x509: certificate is not authorized to sign other certificates"
	case Expired:
		return "x509: certificate has expired or is not yet valid"
	case CANotAuthorizedForThisName:
		return "x509: a root or intermediate certificate is not authorized to sign in this domain"
	case TooManyIntermediates:
		return "x509: too many intermediates for path length constraint"
	case IncompatibleUsage:
		return "x509: certificate specifies an incompatible key usage"
	case NameMismatch:
		return "x509: issuer name does not match subject from issuing certificate"
	}
	return "x509: unknown error"
}

var errNotParsed = errors.New("x509: missing ASN.1 contents; use ParseCertificate")

func matchNameConstraint(domain, constraint string) bool {
	// The meaning of zero length constraints is not specified, but this
	// code follows NSS and accepts them as valid for everything.
	if len(constraint) == 0 {
		return true
	}

	if len(domain) < len(constraint) {
		return false
	}

	prefixLen := len(domain) - len(constraint)
	if !strings.EqualFold(domain[prefixLen:], constraint) {
		return false
	}

	if prefixLen == 0 {
		return true
	}

	isSubdomain := domain[prefixLen-1] == '.'
	constraintHasLeadingDot := constraint[0] == '.'
	return isSubdomain != constraintHasLeadingDot
}
func isValid(c *x509.Certificate, certType int, currentChain []*x509.Certificate, opts *VerifyOptions) error {
	if len(currentChain) > 0 {
		child := currentChain[len(currentChain)-1]
		if !bytes.Equal(child.RawIssuer, c.RawSubject) {
			return CertificateInvalidError{c, NameMismatch}
		}
	}

	now := opts.CurrentTime
	if now.IsZero() {
		now = time.Now()
	}
	if now.Before(c.NotBefore) || now.After(c.NotAfter) {
		return CertificateInvalidError{c, Expired}
	}

	if len(c.PermittedDNSDomains) > 0 {
		ok := false
		for _, constraint := range c.PermittedDNSDomains {
			ok = matchNameConstraint(opts.DNSName, constraint)
			if ok {
				break
			}
		}

		if !ok {
			return CertificateInvalidError{c, CANotAuthorizedForThisName}
		}
	}

	// KeyUsage status flags are ignored. From Engineering Security, Peter
	// Gutmann: A European government CA marked its signing certificates as
	// being valid for encryption only, but no-one noticed. Another
	// European CA marked its signature keys as not being valid for
	// signatures. A different CA marked its own trusted root certificate
	// as being invalid for certificate signing. Another national CA
	// distributed a certificate to be used to encrypt data for the
	// country’s tax authority that was marked as only being usable for
	// digital signatures but not for encryption. Yet another CA reversed
	// the order of the bit flags in the keyUsage due to confusion over
	// encoding endianness, essentially setting a random keyUsage in
	// certificates that it issued. Another CA created a self-invalidating
	// certificate by adding a certificate policy statement stipulating
	// that the certificate had to be used strictly as specified in the
	// keyUsage, and a keyUsage containing a flag indicating that the RSA
	// encryption key could only be used for Diffie-Hellman key agreement.

	if certType == intermediateCertificate && (!c.BasicConstraintsValid || !c.IsCA) {
		return CertificateInvalidError{c, NotAuthorizedToSign}
	}

	if c.BasicConstraintsValid && c.MaxPathLen >= 0 {
		numIntermediates := len(currentChain) - 1
		if numIntermediates > c.MaxPathLen {
			return CertificateInvalidError{c, TooManyIntermediates}
		}
	}

	return nil
}

// Verify attempts to verify c by building one or more chains from c to a
// certificate in opts.Roots, using certificates in opts.Intermediates if
// needed. If successful, it returns one or more chains where the first
// element of the chain is c and the last element is from opts.Roots.
//
// If opts.Roots is nil and system roots are unavailable the returned error
// will be of type SystemRootsError.
//
// WARNING: this doesn't do any revocation checking.
func Verify(c *x509.Certificate, opts VerifyOptions) (chains [][]*x509.Certificate, err error) {
	// Platform-specific verification needs the ASN.1 contents so
	// this makes the behavior consistent across platforms.
	if len(c.Raw) == 0 {
		return nil, errNotParsed
	}
	if opts.Intermediates != nil {
		for _, intermediate := range opts.Intermediates.certs {
			if len(intermediate.Raw) == 0 {
				return nil, errNotParsed
			}
		}
	}

	// Use Windows's own verification and chain building.
	if opts.Roots == nil && runtime.GOOS == "windows" {
		return systemVerify(c, &opts)
	}

	if len(c.UnhandledCriticalExtensions) > 0 {
		return nil, x509.UnhandledCriticalExtension{}
	}

	if opts.Roots == nil {
		opts.Roots = systemRootsPool()
		if opts.Roots == nil {
			return nil, x509.SystemRootsError{systemRootsErr}
		}
	}

	err = isValid(c, leafCertificate, nil, &opts)
	if err != nil {
		return
	}

	if len(opts.DNSName) > 0 {
		err = c.VerifyHostname(opts.DNSName)
		if err != nil {
			return
		}
	}

	var candidateChains [][]*x509.Certificate
	if opts.Roots.contains(c) {
		candidateChains = append(candidateChains, []*x509.Certificate{c})
	} else {
		if candidateChains, err = buildChains(c, make(map[int][][]*x509.Certificate), []*x509.Certificate{c}, &opts); err != nil {
			return nil, err
		}
	}

	keyUsages := opts.KeyUsages
	if len(keyUsages) == 0 {
		keyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}

	// If any key usage is acceptable then we're done.
	for _, usage := range keyUsages {
		if usage == x509.ExtKeyUsageAny {
			chains = candidateChains
			return
		}
	}

	for _, candidate := range candidateChains {
		if checkChainForKeyUsage(candidate, keyUsages) {
			chains = append(chains, candidate)
		}
	}

	if len(chains) == 0 {
		err = CertificateInvalidError{c, IncompatibleUsage}
	}

	return
}
func appendToFreshChain(chain []*x509.Certificate, cert *x509.Certificate) []*x509.Certificate {
	n := make([]*x509.Certificate, len(chain)+1)
	copy(n, chain)
	n[len(chain)] = cert
	return n
}
func buildChains(c *x509.Certificate, cache map[int][][]*x509.Certificate, currentChain []*x509.Certificate, opts *VerifyOptions) (chains [][]*x509.Certificate, err error) {
	possibleRoots, failedRoot, rootErr := opts.Roots.findVerifiedParents(c)
nextRoot:
	for _, rootNum := range possibleRoots {
		root := opts.Roots.certs[rootNum]

		for _, cert := range currentChain {
			if cert.Equal(root) {
				continue nextRoot
			}
		}

		err = isValid(root, rootCertificate, currentChain, opts)
		if err != nil {
			continue
		}
		chains = append(chains, appendToFreshChain(currentChain, root))
	}

	possibleIntermediates, failedIntermediate, intermediateErr := opts.Intermediates.findVerifiedParents(c)
nextIntermediate:
	for _, intermediateNum := range possibleIntermediates {
		intermediate := opts.Intermediates.certs[intermediateNum]
		for _, cert := range currentChain {
			if cert.Equal(intermediate) {
				continue nextIntermediate
			}
		}
		err = isValid(intermediate, intermediateCertificate, currentChain, opts)
		if err != nil {
			continue
		}
		var childChains [][]*x509.Certificate
		childChains, ok := cache[intermediateNum]
		if !ok {
			childChains, err = buildChains(intermediate, cache, appendToFreshChain(currentChain, intermediate), opts)
			cache[intermediateNum] = childChains
		}
		chains = append(chains, childChains...)
	}

	if len(chains) > 0 {
		err = nil
	}

	if len(chains) == 0 && err == nil {
		hintErr := rootErr
		hintCert := failedRoot
		if hintErr == nil {
			hintErr = intermediateErr
			hintCert = failedIntermediate
		}
		err = UnknownAuthorityError{c, hintErr, hintCert}
	}

	return
}

type UnknownAuthorityError struct {
	Cert *x509.Certificate
	// hintErr contains an error that may be helpful in determining why an
	// authority wasn't found.
	hintErr error
	// hintCert contains a possible authority certificate that was rejected
	// because of the error in hintErr.
	hintCert *x509.Certificate
}

func (e UnknownAuthorityError) Error() string {
	s := "x509: certificate signed by unknown authority"
	if e.hintErr != nil {
		certName := e.hintCert.Subject.CommonName
		if len(certName) == 0 {
			if len(e.hintCert.Subject.Organization) > 0 {
				certName = e.hintCert.Subject.Organization[0]
			} else {
				certName = "serial:" + e.hintCert.SerialNumber.String()
			}
		}
		s += fmt.Sprintf(" (possibly because of %q while trying to verify candidate authority certificate %q)", e.hintErr, certName)
	}
	return s
}

func checkChainForKeyUsage(chain []*x509.Certificate, keyUsages []x509.ExtKeyUsage) bool {
	usages := make([]x509.ExtKeyUsage, len(keyUsages))
	copy(usages, keyUsages)

	if len(chain) == 0 {
		return false
	}

	usagesRemaining := len(usages)

	// We walk down the list and cross out any usages that aren't supported
	// by each certificate. If we cross out all the usages, then the chain
	// is unacceptable.

NextCert:
	for i := len(chain) - 1; i >= 0; i-- {
		cert := chain[i]
		if len(cert.ExtKeyUsage) == 0 && len(cert.UnknownExtKeyUsage) == 0 {
			// The certificate doesn't have any extended key usage specified.
			continue
		}

		for _, usage := range cert.ExtKeyUsage {
			if usage == x509.ExtKeyUsageAny {
				// The certificate is explicitly good for any usage.
				continue NextCert
			}
		}

		const invalidUsage x509.ExtKeyUsage = -1

	NextRequestedUsage:
		for i, requestedUsage := range usages {
			if requestedUsage == invalidUsage {
				continue
			}

			for _, usage := range cert.ExtKeyUsage {
				if requestedUsage == usage {
					continue NextRequestedUsage
				} else if requestedUsage == x509.ExtKeyUsageServerAuth &&
					(usage == x509.ExtKeyUsageNetscapeServerGatedCrypto ||
						usage == x509.ExtKeyUsageMicrosoftServerGatedCrypto) {
					// In order to support COMODO
					// certificate chains, we have to
					// accept Netscape or Microsoft SGC
					// usages as equal to ServerAuth.
					continue NextRequestedUsage
				}
			}

			usages[i] = invalidUsage
			usagesRemaining--
			if usagesRemaining == 0 {
				return false
			}
		}
	}

	return true
}
