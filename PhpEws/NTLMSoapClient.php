<?php
/**
 * Soap Client using Microsoft's NTLM Authentication.
 *
 * Copyright (c) 2008 Invest-In-France Agency http://www.invest-in-france.org
 *
 * Author : Thomas Rabaix
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * @link http://rabaix.net/en/articles/2008/03/13/using-soap-php-with-ntlm-authentication
 * @author Thomas Rabaix
 *
 * @package php-ews
 * @subpackage NTLM
 */

namespace PhpEws;

use SoapClient;

/**
 * Soap Client using Microsoft's NTLM Authentication.
 */
class NTLMSoapClient extends SoapClient
{
    /**
     * cURL resource used to make the SOAP request
     *
     * @var resource
     */
    protected $ch;

    /**
     * Whether or not to validate ssl certificates
     *
     * @var boolean
     */
    protected $validate = false;

    /**
     * Performs a SOAP request
     *
     * @link http://php.net/manual/en/function.soap-soapclient-dorequest.php
     *
     * @param string $request the xml soap request
     * @param string $location the url to request
     * @param string $action the soap action.
     * @param integer $version the soap version
     * @param integer $one_way
     * @return string the xml soap response.
     */
    public function __doRequest($request, $location, $action, $version, $one_way = 0)
    {
        $headers = array(
            'Method: POST',
            'Connection: Keep-Alive',
            'User-Agent: PHP-SOAP-CURL',
            'Content-Type: text/xml; charset=utf-8',
            'SOAPAction: "'.$action.'"',
        );

        $this->__last_request_headers = $headers;
        $this->ch = curl_init($location);

        curl_setopt($this->ch, CURLOPT_SSL_VERIFYPEER, $this->validate);
        curl_setopt($this->ch, CURLOPT_SSL_VERIFYHOST, $this->validate);
        curl_setopt($this->ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($this->ch, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($this->ch, CURLOPT_POST, true );
        curl_setopt($this->ch, CURLOPT_POSTFIELDS, $request);
        curl_setopt($this->ch, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
        curl_setopt($this->ch, CURLOPT_HTTPAUTH, CURLAUTH_BASIC | CURLAUTH_NTLM);
        curl_setopt($this->ch, CURLOPT_USERPWD, $this->user.':'.$this->password);
        curl_setopt($this->ch, CURLOPT_CONNECTTIMEOUT, 10);

        $response = curl_exec($this->ch);

        // TODO: Add some real error handling.
        // If the response if false than there was an error and we should throw
        // an exception.
        if ($response === false) {
            throw new EWSException(
              'Curl error: ' . curl_error($this->ch),
              curl_errno($this->ch)
            );
        }

        return $this->sanitizeXml($response);
    }
    
    /**
     * Sanitize XML returned by EWS
     *
     * @param $xml
     * @return string
     */
    public function sanitizeXml($xml)
    {
        // Illegal HTML entities (http://do.remifa.so/archives/unicode/latin1.html)
        $patterns = [
            '/&#x0;/i', '/&#x1;/i', '/&#x2;/i', '/&#x3;/i', '/&#x4;/i', '/&#x5;/i', '/&#x6;/i',
            '/&#x7;/i', '/&#x8;/i', '/&#xb;/i', '/&#xc;/i', '/&#xe;/i', '/&#xf;/i', '/&#x10;/i',
            '/&#x11;/i', '/&#x12;/i', '/&#x13;/i', '/&#x14;/i', '/&#x15;/i', '/&#x16;/i', '/&#x17;/i',
            '/&#x18;/i', '/&#x19;/i', '/&#x1a;/i', '/&#x1b;/i', '/&#x1c;/i', '/&#x1d;/i', '/&#x1e;/i',
            '/&#x1f;/i', '/&#x7f;/i', '/&#x80;/i', '/&#x81;/i', '/&#x82;/i', '/&#x83;/i', '/&#x84;/i',
            '/&#x85;/i', '/&#x86;/i', '/&#x87;/i', '/&#x88;/i', '/&#x89;/i', '/&#x8a;/i', '/&#x8b;/i',
            '/&#x8c;/i', '/&#x8d;/i', '/&#x8e;/i', '/&#x8f;/i', '/&#x90;/i', '/&#x91;/i', '/&#x92;/i',
            '/&#x93;/i', '/&#x94;/i', '/&#x95;/i', '/&#x96;/i', '/&#x97;/i', '/&#x98;/i', '/&#x99;/i',
            '/&#x9a;/i', '/&#x9b;/i', '/&#x9c;/i', '/&#x9d;/i', '/&#x9e;/i', '/&#x9f;/i'
        ];
        return preg_replace($patterns, '', $xml);
    }

    /**
     * Returns last SOAP request headers
     *
     * @link http://php.net/manual/en/function.soap-soapclient-getlastrequestheaders.php
     *
     * @return string the last soap request headers
     */
    public function __getLastRequestHeaders()
    {
        return implode('n', $this->__last_request_headers) . "\n";
    }

    /**
     * Sets whether or not to validate ssl certificates
     *
     * @param boolean $validate
     */
    public function validateCertificate($validate = true)
    {
        $this->validate = $validate;

        return true;
    }
}
