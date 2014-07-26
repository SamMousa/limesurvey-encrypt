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


        public function actionExport($surveyId)
        {
            $table = $this->api->getTable($this, 'responses');
            $data = $table->findAllByAttributes(array(
                'survey_id' => $surveyId
            ));
            $content = '';
            foreach ($data as $record)
            {
                $content.= base64_encode($record->response) . "\n";
            }
            $this->event->get('request')->sendFile('encrypted.dat', $content, 'text/plain', true);
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
            if (openssl_public_encrypt(json_encode($response),$crypted, $this->get('publicKey')))
            {
                $encrypted = $this->pluginManager->getAPI()->newModel($this, 'responses');
                $encrypted->response = $crypted;
                $encrypted->survey_id = $event->get('surveyId');
                if ($encrypted->save())
                {
                    $this->pluginManager->getAPI()->removeResponse($event->get('surveyId'), $event->get('responseId'));
                    $this->event->setContent($this, 'Response has been encrypted.');
                    return;
                }

            }

            $this->event->setContent($this, 'Response could not be encrypted.');
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
