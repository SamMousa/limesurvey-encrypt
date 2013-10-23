<?php
$key = openssl_pkey_get_private(file_get_contents('f:/key.priv'));
$responses = file('f:/encrypted.dat', FILE_IGNORE_NEW_LINES + FILE_SKIP_EMPTY_LINES);
$errors = 0;
$handle = fopen('php://stdout', 'w');
$first = true;

foreach ($responses as $encrypted)
{
	if (openssl_private_decrypt(base64_decode($encrypted), $result, $key))
	{
		$response = json_decode($result, true);
		if ($first)
		{
			fputcsv($handle, array_keys($response));
			$first = false;
		}
		fputcsv($handle, $response);
		unset($result);
		
	}
	else
	{
		$errors++;
	}
}
?>
