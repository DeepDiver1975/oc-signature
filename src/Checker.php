<?php

namespace OC\Signature;

use OC\Signature\Exceptions\InvalidSignatureException;
use OC\Signature\Iterator\ExcludeFileByNameFilterIterator;
use phpseclib\Crypt\RSA;
use phpseclib\File\X509;

/**
 * Class Checker handles the code signing using X.509 and RSA. ownCloud ships with
 * a public root certificate certificate that allows to issue new certificates that
 * will be trusted for signing code. The CN will be used to verify that a certificate
 * given to a third-party developer may not be used for other applications. For
 * example the author of the application "calendar" would only receive a certificate
 * only valid for this application.
 *
 * @package OC\Signature
 */
class Checker {

    private $crl;
    private $crt;

    public function __construct($crl = null, $crt = null) {
        if (is_null($crl)) {
            $crl = __DIR__ . '/../resources/intermediate.crl.pem';
        }
        if (is_null($crt)) {
            $crt = __DIR__ . '/../resources/root.crt';
        }
        $this->crl = $crl;
        $this->crt = $crt;
    }

    /**
	 * Enumerates all files belonging to the folder. Sensible defaults are excluded.
	 *
	 * @param string $folderToIterate
	 * @return \RecursiveIteratorIterator
	 * @throws \Exception
	 */
	private function getFolderIterator($folderToIterate) {
		$dirItr = new \RecursiveDirectoryIterator(
			$folderToIterate,
			\RecursiveDirectoryIterator::SKIP_DOTS
		);

		$excludeGenericFilesIterator = new ExcludeFileByNameFilterIterator($dirItr);

		return new \RecursiveIteratorIterator(
			$excludeGenericFilesIterator,
			\RecursiveIteratorIterator::SELF_FIRST
		);
	}

	/**
	 * Returns an array of ['filename' => 'SHA512-hash-of-file'] for all files found
	 * in the iterator.
	 *
	 * @param \RecursiveIteratorIterator $iterator
	 * @param string $path
	 * @return array Array of hashes.
	 */
	private function generateHashes(\RecursiveIteratorIterator $iterator,
									$path) {
		$hashes = [];

		$baseDirectoryLength = strlen($path);
		foreach($iterator as $filename => $data) {
			/** @var \DirectoryIterator $data */
			if($data->isDir()) {
				continue;
			}

			$relativeFileName = substr($filename, $baseDirectoryLength);
			$relativeFileName = ltrim($relativeFileName, '/');

			// Exclude signature.json files in the appinfo and root folder
			if($relativeFileName === 'appinfo/signature.json') {
				continue;
			}

			$hashes[$relativeFileName] = hash_file('sha512', $filename);
		}

		return $hashes;
	}

	/**
	 * Creates the signature data
	 *
	 * @param array $hashes
	 * @param X509 $certificate
	 * @param RSA $privateKey
	 * @return string
	 */
	private function createSignatureData(array $hashes,
										 X509 $certificate,
										 RSA $privateKey) {
		ksort($hashes);

		$privateKey->setSignatureMode(RSA::SIGNATURE_PSS);
		$privateKey->setSaltLength(0);
		$privateKey->setMGFHash('sha512');
		$signature = $privateKey->sign(json_encode($hashes));

		return [
				'hashes' => $hashes,
				'signature' => base64_encode($signature),
				'certificate' => $certificate->saveX509($certificate->currentCert),
			];
	}

	/**
	 * Write the signature of the app in the specified folder
	 *
	 * @param string $path
	 * @param X509 $certificate
	 * @param RSA $privateKey
	 * @throws \Exception
	 */
	public function writeAppSignature($path,
									  X509 $certificate,
									  RSA $privateKey) {
		if(!is_dir($path)) {
			throw new \Exception('Directory does not exist.');
		}
		$iterator = $this->getFolderIterator($path);
		$hashes = $this->generateHashes($iterator, $path);
		$signature = $this->createSignatureData($hashes, $certificate, $privateKey);
		file_put_contents(
				$path . '/appinfo/signature.json',
				json_encode($signature, JSON_PRETTY_PRINT)
		);
	}

	/**
	 * Verifies the signature for the specified path.
	 *
	 * @param string $signaturePath
	 * @param string $basePath
	 * @param string $certificateCN
	 * @return array
	 * @throws InvalidSignatureException
	 * @throws \Exception
	 */
	private function verify($signaturePath, $basePath, $certificateCN) {
		$signatureData = json_decode(file_get_contents($signaturePath), true);
		if(!is_array($signatureData)) {
			throw new InvalidSignatureException('Signature data not found.');
		}

		$expectedHashes = $signatureData['hashes'];
		ksort($expectedHashes);
		$signature = base64_decode($signatureData['signature']);
		$certificate = $signatureData['certificate'];

		// Check if certificate is signed by ownCloud Root Authority
		$x509 = new \phpseclib\File\X509();
		$rootCertificatePublicKey = file_get_contents($this->crt);
		$x509->loadCA($rootCertificatePublicKey);
		$loadedCertificate = $x509->loadX509($certificate);
		if(!$x509->validateSignature()) {
			throw new InvalidSignatureException('App Certificate is not valid.');
		}

		// Check if the certificate has been revoked
		$crlFileContent = file_get_contents($this->crl);
		if ($crlFileContent && strlen($crlFileContent) > 0) {
			$crl = new \phpseclib\File\X509();
			$crl->loadCA($rootCertificatePublicKey);
			$crl->loadCRL($crlFileContent);
			if(!$crl->validateSignature()) {
				throw new InvalidSignatureException('Certificate Revocation List is not valid.');
			}
			// Get the certificate's serial number.
			$csn = $loadedCertificate['tbsCertificate']['serialNumber']->toString();

			// Check certificate revocation status.
			$revoked = $crl->getRevoked($csn);
			if ($revoked) {
				throw new InvalidSignatureException('Certificate has been revoked.');
			}
		}

		// Verify if certificate has proper CN. "core" CN is always trusted.
		if($x509->getDN(X509::DN_OPENSSL)['CN'] !== $certificateCN && $x509->getDN(X509::DN_OPENSSL)['CN'] !== 'core') {
			throw new InvalidSignatureException(
					sprintf('Certificate is not valid for required scope. (Requested: %s, current: %s)', $certificateCN, $x509->getDN(true))
			);
		}

		// Check if the signature of the files is valid
		$rsa = new \phpseclib\Crypt\RSA();
		$rsa->loadKey($x509->currentCert['tbsCertificate']['subjectPublicKeyInfo']['subjectPublicKey']);
		$rsa->setSignatureMode(RSA::SIGNATURE_PSS);
        $rsa->setSaltLength(0);
		$rsa->setMGFHash('sha512');
		if(!$rsa->verify(json_encode($expectedHashes), $signature)) {
			throw new InvalidSignatureException('Signature could not get verified.');
		}

		// Compare the list of files which are not identical
		$currentInstanceHashes = $this->generateHashes($this->getFolderIterator($basePath), $basePath);
		$differencesA = array_diff($expectedHashes, $currentInstanceHashes);
		$differencesB = array_diff($currentInstanceHashes, $expectedHashes);
		$differences = array_unique(array_merge($differencesA, $differencesB));
		$differenceArray = [];
		foreach($differences as $filename => $hash) {
			// Check if file should not exist in the new signature table
			if(!array_key_exists($filename, $expectedHashes)) {
				$differenceArray['EXTRA_FILE'][$filename]['expected'] = '';
				$differenceArray['EXTRA_FILE'][$filename]['current'] = $hash;
				continue;
			}

			// Check if file is missing
			if(!array_key_exists($filename, $currentInstanceHashes)) {
				$differenceArray['FILE_MISSING'][$filename]['expected'] = $expectedHashes[$filename];
				$differenceArray['FILE_MISSING'][$filename]['current'] = '';
				continue;
			}

			// Check if hash does mismatch
			if($expectedHashes[$filename] !== $currentInstanceHashes[$filename]) {
				$differenceArray['INVALID_HASH'][$filename]['expected'] = $expectedHashes[$filename];
				$differenceArray['INVALID_HASH'][$filename]['current'] = $currentInstanceHashes[$filename];
				continue;
			}

			// Should never happen.
			throw new \Exception('Invalid behaviour in file hash comparison experienced. Please report this error to the developers.');
		}

		return $differenceArray;
	}

	/**
	 * Verify the signature of $appId. Returns an array with the following content:
	 * [
	 * 	'FILE_MISSING' =>
	 * 	[
	 * 		'filename' => [
	 * 			'expected' => 'expectedSHA512',
	 * 			'current' => 'currentSHA512',
	 * 		],
	 * 	],
	 * 	'EXTRA_FILE' =>
	 * 	[
	 * 		'filename' => [
	 * 			'expected' => 'expectedSHA512',
	 * 			'current' => 'currentSHA512',
	 * 		],
	 * 	],
	 * 	'INVALID_HASH' =>
	 * 	[
	 * 		'filename' => [
	 * 			'expected' => 'expectedSHA512',
	 * 			'current' => 'currentSHA512',
	 * 		],
	 * 	],
	 * ]
	 *
	 * Array may be empty in case no problems have been found.
	 *
	 * @param string $appId
	 * @param string $path
	 * @return array
	 */
	public function verifyAppSignature($appId, $path) {
		try {
			$result = $this->verify(
					$path . '/appinfo/signature.json',
					$path,
					$appId
			);
		} catch (\Exception $e) {
			$result = [
					'EXCEPTION' => [
							'class' => get_class($e),
							'message' => $e->getMessage(),
					],
			];
		}

		return $result;
	}
}
