package dkg

import "errors"

var (
	errRound1DataElements    = errors.New("invalid number of expected round 1 data packets")
	errRound2DataElements    = errors.New("invalid number of expected round 2 data packets")
	errRound2InvalidReceiver = errors.New("invalid receiver in round 2 package")
	errInvalidSignature      = errors.New("invalid signature")

	errCommitmentNotFound      = errors.New("commitment not found for participant")
	errInvalidSecretShare      = errors.New("invalid secret share received from peer")
	errVerificationShareFailed = errors.New("failed to compute correct verification share")
)
