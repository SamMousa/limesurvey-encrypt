<?php 

    /**
     * This plugin uses asymmetric encryption to encrypt responses after completion.
     * Even if the limesurvey server is compromised an attack will have no way of decrypting the data.
     *
     * This work was commissioned by Dr Mark Brown
     * @author Sam Mousa MSc <sam@befound.nl>
     * @license http://opensource.org/licenses/MIT MIT
     * @link http://www.markgbrown.com/
     *
     */
    class Encrypt extends PluginBase
    {
        static protected $description = 'Encrypt: Encrypt completed surveys.';
        static protected $name = 'Encrypt';

        /**
         * Plugin settings
         */
        protected $settings = array(
            'publicKey' => array(
                'type' => 'text',
                'label' => 'Public key'
            ),
           );
        protected $storage = 'DbStorage';
        
        public function __construct(PluginManager $manager, $id) 
        {
            parent::__construct($manager, $id);
            
            // Provides survey specific settings.
            $this->subscribe('beforeSurveySettings');
            
            // Saves survey specific settings.
            $this->subscribe('newSurveySettings');
            
            // Encrypt data on survey completion.
            $this->subscribe('afterSurveyComplete');

            // Create table for encrypted data.
            $this->subscribe('beforeActivate');

            $this->subscribe('newDirectRequest');
        }

        protected function getData($surveyId)
        {
            $table = $this->api->getTable($this, 'responses');
            $responses = $table->findAllByAttributes(array(
                'survey_id' => $surveyId
            ));
            $data = '';
            return implode('.', array_map(function($response) { return base64_encode($response->response); }, $responses));
        }
        
        public function actionExportScript($surveyId)
        {
            $data = $this->getData($surveyId);

            $script = file(__DIR__ . '/decrypt.php', FILE_IGNORE_NEW_LINES);
            // Remove first line.
            array_shift($script);

            $script[] = 'decryptResponses($privateKey, \'' . $data . '\', $handle);';

            $lines = [];
            $lines[] = '@echo off';
            $lines['call'] = "php -r \"\$f = fopen('%~0', 'rb'); fseek(\$f, ----------); \$code = stream_get_contents(\$f); eval(\$code); \"";
            $lines[] = 'exit';
            $offset = strlen(implode("\n", $lines)) - 1;
            $lines['call'] = strtr($lines['call'], ['----------' => $offset]);
            // Add data.
            $lines = array_merge($lines, $script);
            $lines[] = 'fgets($stdin);';
            $this->event->get('request')->sendFile('encrypted.cmd',  implode("\n", $lines), 'text/plain', true);
        }

        public function actionExport($surveyId)
        {
            $this->actionExportScript($surveyId);
            return;
            $data = $this->getData($surveyId);
            $this->event->get('request')->sendFile('encrypted.dat', $data, 'text/plain', true);
        }

        /**
         * This event is fired after the survey has been completed.
         * @param PluginEvent $event
         */
        public function afterSurveyComplete()
        {
            $event = $this->getEvent();
            if ($event->get('responseId') == null)
            {
                return;
            }

            // Get the response information.
            $response = $this->api->getResponse($event->get('surveyId'), $event->get('responseId'));
            $publicKey = $this->get('publicKey');
            
            $data = json_encode($response);

            $encryptedResponse = $this->pluginManager->getAPI()->newModel($this, 'responses');
            $encryptedResponse->response = $this->encrypt($publicKey, $data);
            $encryptedResponse->survey_id = $event->get('surveyId');

            if ($encryptedResponse->save())
            {
                $this->pluginManager->getAPI()->removeResponse($event->get('surveyId'), $event->get('responseId'));
                $this->event->setContent($this, 'Response has been encrypted.');
                return;
            }
            $this->event->setContent($this, openssl_error_string());
        }

        public function beforeActivate()
        {
            $event = $this->event;
            if (!$this->api->tableExists($this, 'responses'))
            {
                    $this->api->createTable($this, 'responses', array(
                    'survey_id' => 'int',
                    'response' => 'binary',
                ));
            }
            return true;
            
        }
        public function beforeSurveySettings()
        {
            $event = $this->event;
            $table = $this->api->getTable($this, 'responses');
            $count = $table->countByAttributes(array('survey_id' => $event->get('survey')));
            $settings = array(
                'name' => get_class($this),
                'settings' => array(
                    'enabled' => array(
                        'type' => 'boolean',
                        'label' => 'Encrypt responses for this survey: ',
                        'current' => $this->get('enabled', 'Survey', $event->get('survey'), true)
                    ),
                    
                    'count' => array(
                        'label' => 'Number of encrypted responses:',
                        'type' => 'string',
                        'readOnly' => true,
                        'current' => $count
                    )
                )
             );

            if ($count > 0)
            {
                $settings['settings']['export'] =array(
                    'label' => 'Export data',
                    'type' => 'link',
                    'link' => $this->api->createUrl('plugins/direct', array('plugin' => 'Encrypt', 'function' => 'export', 'sid' => $event->get('survey')))
                );
            }
            $event->set("surveysettings.{$this->id}", $settings);

        }

        protected function encrypt($publicKey, $data)
        {
            // Generate a random password for symmetric encryption.
            $symmetricKey = openssl_random_pseudo_bytes(50);
            $encryptedKey = '';
            if (openssl_public_encrypt($symmetricKey, $encryptedKey, $publicKey))
            {
                // Use the encrypted key as basis for the IV.
                $iv = substr($encryptedKey, 0, mcrypt_get_iv_size(MCRYPT_BLOWFISH, MCRYPT_MODE_CBC));
                $encryptedData = mcrypt_encrypt(MCRYPT_BLOWFISH, $symmetricKey, $data, MCRYPT_MODE_CBC, $iv);
                // Key has constant length so no separator is necessary.
                return $encryptedKey . $encryptedData;
            }
            /**
             * @todo Proper error handling.
             * 
             */
            

        }
        public function newDirectRequest()
        {
            $event = $this->event;
            if ($event->get('target') == $this->getName() && $event->get('function') == 'export')
            {
                if (!$this->api->checkAccess('administrator'))
                {
                    throw new CHttpException(403, 'This action requires you to be logged in as super administrator.');
                }
                elseif ($event->get('request')->getParam('sid') == null)
                {
                    throw new CHttpException(400, 'Survey id missing; pass it as sid variable.');
                }
                else
                {
                    $this->actionExport($event->get('request')->getParam('sid'));
                }
            }

            

        }

        public function newSurveySettings()
        {
            foreach ($this->event->get('settings') as $name => $value)
            {
                if ($name != 'count')
                {
                    $this->set($name, $value, 'Survey', $this->event->get('survey'));
                }
            }
        }

    }


?>
