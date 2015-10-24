if (window.FormData !== undefined) {
	formData = new FormData()
}

function status(response) {
	if (response.status >= 200 && response.status < 300) {
		console.log('All good')
	} else {
		if (response.status == 400) {
			console.log('No cert for you!')
		}
		return Promise.reject(new Error(response.statusText))
	}
}

function check() {
	oForm = document.forms["transferInfo"];
	console.log("Name:" + oForm["buyer"].value)

	var bodyText = "buyer=" + oForm["buyer"].value


	// Generate a secure RSA keypair
	console.log("Generating keypair")
	var rsa = forge.pki.rsa;
	var keypair = rsa.generateKeyPair({
		bits: 2048,
		e: 0x10001
	});
	console.log("Keypair made")

	// Create a certification request (CSR) using the keypair and the encrypted
	// data
	var csr = forge.pki.createCertificationRequest();
	csr.publicKey = keypair.publicKey;

	console.log("CSR made and public key added")

	csr.setSubject([{
		name: 'commonName',
		value: 'Taylor.Andrew.Wrobel'
	}, {
		name: 'countryName',
		value: 'US'
	}, {
		shortName: 'ST',
		value: 'California'
	}, {
		name: 'localityName',
		value: 'San Francisco'
	}, {
		name: 'organizationName',
		value: 'ATF'
	}, {
		shortName: 'OU',
		value: 'NA'
	}]);
	// set (optional) attributes
	csr.setAttributes([{
		name: 'challengePassword',
		value: 'password'
	}, {
		// unstrcutredName is used to store the transfer information which has been encrypted.
		name: 'unstructuredName',
		value: 'SuperDuperSecretInfo'
	}]);

	// sign certification request
	csr.sign(keypair.privateKey);

	console.log("CSR signed")

	// verify certification request
	var verified = csr.verify();

	// convert certification request to PEM-format
	var pem = forge.pki.certificationRequestToPem(csr);

	console.log("CSR converted to PEM - sending to server")

	fetch("/check", {
			method: 'post',
			headers: {
				"Content-type": "application/pkcs10"
			},
			body: pem
		})
		.then(status)
		.then(function(data) {
			console.log('Request succeeded with JSON response', data);
		})
		.catch(function(error) {
			console.log('Request failed', error);
		});
}
