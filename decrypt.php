<?php

    function decryptResponses($privateKey, $data, $handle)
    {
		$first = true;
        foreach (explode('.', $data) as $encryptedResponse)
        {
			echo "Decrypting response...\n";
			$decryptedKey = '';
			$allData = base64_decode($encryptedResponse);
			$encryptedKey = substr($allData, 0, 128);
            if (openssl_private_decrypt($encryptedKey, $decryptedKey, $privateKey))
            {
				$iv = substr($encryptedKey, 0, mcrypt_get_iv_size(MCRYPT_BLOWFISH, MCRYPT_MODE_CBC));
				$data = mcrypt_decrypt(MCRYPT_BLOWFISH, $decryptedKey, substr($allData, 128), MCRYPT_MODE_CBC, $iv);
				$response = json_decode(trim($data), true);
				if ($first)
                {
                    fputcsv($handle, array_keys($response));
                    $first = false;
                }
                fputcsv($handle, $response);
                unset($response);
            }
			else
			{
				echo openssl_error_string() . "\n";
			}
        }
    }

	$stdin = fopen('php://stdin', 'r');
    if (isset($argv[1]))
    {
        $privateKey = openssl_pkey_get_private(file_get_contents($argv[1]));
    }
    else
    {
		echo "Please enter the path to the private key file: ";
		$file = rtrim(fgets($stdin));
		echo '"' . $file . '"' . PHP_EOL;
		$key = file_get_contents($file);
		$privateKey = openssl_pkey_get_private($key);
    }

	$handle = fopen('php://stdout', 'w');
	/**
	 * The builder script will add the appropriate decrypt command to the end
	 * of the file. DO NOT ADD A CLOSING TAG.
	 */