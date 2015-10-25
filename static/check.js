if (window.FormData !== undefined) {
	formData = new FormData()
}

function status(response) {
	if (response.status >= 200 && response.status < 300) {
		console.log('All good')
		console.log(response);
		return Promise.resolve(response)
	} else {
		if (response.status == 400) {
			console.log('No cert for you!')
		}
		return Promise.reject(new Error(response.statusText))
	}
}

function resetForm() {
	document.forms["transferInfo"].reset();
	console.log("Reset")
}

function check() {

	// Get the form data from the document
	oForm = document.forms["transferInfo"];

	// Separate the form data into the public and private components
	var pubData = {
		firstName: oForm["buyerFirst"].value,
		middleName: oForm["buyerMiddle"].value,
		lastName: oForm["buyerLast"].value
	}

	if (oForm["buyerSSN"].value != "") {
		pubData.ssn = oForm["buyerSSN"].value
	} else {
		pubData.dl = oForm["buyerDL"].value
		pubData.dlState = oForm["buyerDLS"].value
	}

	var keySize = oForm["keySize"].value

	console.log(pubData)

	var privData = {
		seller: {
			firstName: oForm["sellerFirst"].value,
			middleName: oForm["sellerMiddle"].value,
			lastName: oForm["sellerLast"].value,
			ffl: oForm["sellerFFL"].value
		},
		gun: {
			manufacturer: oForm["gunManufacturer"].value,
			model: oForm["gunModel"].value,
			variety: oForm["gunType"].value,
			serialNumber: oForm["gunSerial"].value
		}
	}

	// Generate an RSA keypair
	console.log("Generating keypair")
	var rsa = forge.pki.rsa;
	var keypair = rsa.generateKeyPair({
		bits: parseInt(keySize),
		e: 0x10001
	});
	console.log("Keypair made")

	// Use the keypair to encrypt the life out of the private data
	var encPriv = keypair.publicKey.encrypt(JSON.stringify(privData));

	// Create a certification request (CSR) using the keypair and the encrypted
	// data
	var csr = forge.pki.createCertificationRequest();
	csr.publicKey = keypair.publicKey;

	console.log("CSR made and public key added")

	csr.setSubject([{
		name: 'commonName',
		value: btoa(JSON.stringify(pubData))
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
		shortName: 'OU', // Organizational Unit isn't needed.  Let's make use of it for secure data
		value: btoa(encPriv)
	}]);

	// sign certification request
	csr.sign(keypair.privateKey);

	console.log("CSR signed")

	// verify certification request
	var verified = csr.verify();

	// convert certification request to PEM-format
	var csrPem = forge.pki.certificationRequestToPem(csr);

	console.log("CSR converted to PEM - sending to server")

	fetch("/check", {
			method: 'post',
			headers: {
				"Content-type": "application/pkcs10"
			},
			body: csrPem
		})
		.then(status)
		.then(function(data) {
			console.log('Request succeeded with JSON response', data.body);
			window.dummy = data;
			// Download the generated private key using the file saver library
			var pkpem = forge.pki.privateKeyToPem(keypair.privateKey)
			var keyBlob = new Blob([pkpem], {
				type: "application/x-pem-file"
			});
			saveAs(keyBlob, "private-key.pem");

			// Need to wait breifely because of a dumb race condition. HACK HACK HACK
			var millisecondsToWait = 250;
			data.body.getReader().read().then(function(response) {
				console.log(response.value);
				setTimeout(function() {
					var certBlob = new Blob([response.value], {
						type: "application/x-pem-file"
					})
					saveAs(certBlob, "transfer-receipt.pem")
				}, millisecondsToWait);
			});
		})
		.catch(function(error) {
			console.log('Request failed', error);
		});
}
