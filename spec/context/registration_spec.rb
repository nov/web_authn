RSpec.describe WebAuthn::Context::Registration do
  let(:context) { registration_context }
  let(:context_instance) do
    WebAuthn.context_for(
      client_data_json,
      origin: context[:origin],
      challenge: context[:challenge]
    )
  end

  describe '#verify!' do
    let(:credential_id) do
      'Dew0kaZXdMnZjmlgNk_4OlkiS7qteGaFRknmQ02Vojf7jDB-GXb3q0CXnbNK1UNSwtUibj97hqlBZTCXp4addg'
    end
    let(:rp_id_hash) do
      'MsuA3KzDw1JGLLAfO_4wLebzcS8w_SDs0Zw7pbhYlJU'
    end
    let(:flags) do
      WebAuthn::AuthenticatorData::Flags.new(
        up: true, uv: false, be: false, bs: false, at: true, ex: false
      )
    end
    let(:public_key_pem) do
      <<~PEM
      -----BEGIN PUBLIC KEY-----
      MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEmQvMomjF0F3asbDWda13XeA1UbXd
      cS5j3Wg3G1LtgaNlNRc/WstNxVl56t6fVIJuVjMZqon1GpDp/UDDTXO7/g==
      -----END PUBLIC KEY-----
      PEM
    end
    let(:sign_count) { 73 }
    let(:attestation_object) do
      'o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjEMsuA3KzDw1JGLLAfO_4wLebzcS8w_SDs0Zw7pbhYlJVBAAAASQAAAAAAAAAAAAAAAAAAAAAAQA3sNJGmV3TJ2Y5pYDZP-DpZIku6rXhmhUZJ5kNNlaI3-4wwfhl296tAl52zStVDUsLVIm4_e4apQWUwl6eGnXalAQIDJiABIVggmQvMomjF0F3asbDWda13XeA1UbXdcS5j3Wg3G1LtgaMiWCBlNRc_WstNxVl56t6fVIJuVjMZqon1GpDp_UDDTXO7_g'
    end
    subject { context_instance.verify! attestation_object }

    its(:credential_id) { should == credential_id }
    its(:rp_id_hash) { should == rp_id_hash }
    its(:flags) { should == flags }
    its(:public_key) { should be_instance_of OpenSSL::PKey::EC }
    its(:public_cose_key) { should be_instance_of COSE::Key::EC2 }
    its(:public_key_pem) do
      subject.public_key.to_pem.should == public_key_pem
    end
    its(:sign_count) { should == sign_count }

    context 'when packed attestation given' do
      let(:context) do
        {
          origin: 'https://web-authn.self-issued.app',
          challenge: 'random-string-generated-by-rp-server'
        }
      end
      let(:client_data_json) do
        'eyJjaGFsbGVuZ2UiOiJjbUZ1Wkc5dExYTjBjbWx1WnkxblpXNWxjbUYwWldRdFlua3RjbkF0YzJWeWRtVnkiLCJvcmlnaW4iOiJodHRwczovL3dlYi1hdXRobi5zZWxmLWlzc3VlZC5hcHAiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0'
      end

      context 'when self-attestation' do
        let(:attestation_object) do
          'o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnWEYwRAIgOprGUE_GZMIbRBAPLPw6IiNdSk4dxFb4cRbqDgVfFXQCIHnRdm64FfnShyIhq1Z2qfn3ygp0auT32gy-eL35Uo6YaGF1dGhEYXRhWMQyy4DcrMPDUkYssB87_jAt5vNxLzD9IOzRnDuluFiUlUVb2_sTAAAAAAAAAAAAAAAAAAAAAABAAKUVEhUfjXl7S9MbcWXRfXltc39Spl6yuLxOuUtQJ-y-5DkR61Ge8riwY7dRXZFNSaWhsw9LfsknL57eZEB1gKUBAgMmIAEhWCCfkZcOMoafdVwFi4cNNPQlJS1JNUkq34sJ5fKhDODsfyJYIKD89fXxjNhcX6gDxsTwH3VL_TG7HAHdKFgUjAFumfmr'
        end

        it do
          expect do
            subject
          end.not_to raise_error
        end

        context 'when client_data_json is invalid' do
          let(:client_data_json) do
            Base64.urlsafe_encode64({
              type: "webauthn.create",
              challenge: "cmFuZG9tLXN0cmluZy1nZW5lcmF0ZWQtYnktcnAtc2VydmVy",
              origin: "https://web-authn.self-issued.app",
              malformed: 'malformed'
            }.to_json, padding: false)
          end

          it do
            expect do
              subject
            end.to raise_error WebAuthn::InvalidAttestation, 'Invalid Packed Self Attestation: signature'
          end
        end
      end

      context 'otherwise' do
        let(:attestation_object) do
          'o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEgwRgIhANsy4jAv4_BLPmM1pua45Pqo1gfIMA3KDgG-22P0eSH1AiEA3vRxM21j1nKLYyWTdgigzjZHG81IU3JXt2hh0Hr-P_tjeDVjgVkCwjCCAr4wggGmoAMCAQICBHSG_cIwDQYJKoZIhvcNAQELBQAwLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290IENBIFNlcmlhbCA0NTcyMDA2MzEwIBcNMTQwODAxMDAwMDAwWhgPMjA1MDA5MDQwMDAwMDBaMG8xCzAJBgNVBAYTAlNFMRIwEAYDVQQKDAlZdWJpY28gQUIxIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xKDAmBgNVBAMMH1l1YmljbyBVMkYgRUUgU2VyaWFsIDE5NTUwMDM4NDIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASVXfOt9yR9MXXv_ZzE8xpOh4664YEJVmFQ-ziLLl9lJ79XQJqlgaUNCsUvGERcChNUihNTyKTlmnBOUjvATevto2wwajAiBgkrBgEEAYLECgIEFTEuMy42LjEuNC4xLjQxNDgyLjEuMTATBgsrBgEEAYLlHAIBAQQEAwIFIDAhBgsrBgEEAYLlHAEBBAQSBBD4oBHzjApNFYAGFxEfntx9MAwGA1UdEwEB_wQCMAAwDQYJKoZIhvcNAQELBQADggEBADFcSIDmmlJ-OGaJvWn9CqhvSeueToVFQVVvqtALOgCKHdwB-Wx29mg2GpHiMsgQp5xjB0ybbnpG6x212FxESJ-GinZD0ipchi7APwPlhIvjgH16zVX44a4e4hOsc6tLIOP71SaMsHuHgCcdH0vg5d2sc006WJe9TXO6fzV-ogjJnYpNKQLmCXoAXE3JBNwKGBIOCvfQDPyWmiiG5bGxYfPty8Z3pnjX-1MDnM2hhr40ulMxlSNDnX_ZSnDyMGIbk8TOQmjTF02UO8auP8k3wt5D1rROIRU9-FCSX5WQYi68RuDrGMZB8P5-byoJqbKQdxn2LmE1oZAyohPAmLcoPO5oYXV0aERhdGFYxDLLgNysw8NSRiywHzv-MC3m83EvMP0g7NGcO6W4WJSVQQAAAAv4oBHzjApNFYAGFxEfntx9AEA02xXaLwowZrcHlY4sjukQfJOcMH6ulShKwJM5F4ScjEZHw5pzBzgX2Us_FsAqBP4D3f7rnJ3khIHK7bwY6vtYpQECAyYgASFYIJCdNP17MO609HucLCpQWeeCqIDtipNu2yK0PZHMPh1KIlggRfqxNbCUPKGPZn_NLUdXP2Jsf2ErcCoLEq9O7yEpZvQ'
        end

        it do
          expect do
            subject
          end.to raise_error WebAuthn::NotImplementedError, 'Certificate Chain Verification Not Implemented Yet: packed'
        end
      end
    end

    context 'when android-safetynet attestation given' do
      let(:context) do
        {
          origin: 'https://web-authn.self-issued.app',
          challenge: 'random-string-generated-by-rp-server'
        }
      end
      let(:client_data_json) do
        'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiY21GdVpHOXRMWE4wY21sdVp5MW5aVzVsY21GMFpXUXRZbmt0Y25BdGMyVnlkbVZ5Iiwib3JpZ2luIjoiaHR0cHM6XC9cL3dlYi1hdXRobi5zZWxmLWlzc3VlZC5hcHAiLCJhbmRyb2lkUGFja2FnZU5hbWUiOiJjb20uY2hyb21lLmNhbmFyeSJ9'
      end
      let(:attestation_object) do
        'o2NmbXRxYW5kcm9pZC1zYWZldHluZXRnYXR0U3RtdKJjdmVyaDEyODc0MDQxaHJlc3BvbnNlWRMHZXlKaGJHY2lPaUpTVXpJMU5pSXNJbmcxWXlJNld5Sk5TVWxGYVdwRFEwRXpTMmRCZDBsQ1FXZEpTVmxyV1c4MVJqQm5PRFpyZDBSUldVcExiMXBKYUhaalRrRlJSVXhDVVVGM1ZrUkZURTFCYTBkQk1WVkZRbWhOUTFaV1RYaElha0ZqUW1kT1ZrSkJiMVJHVldSMllqSmtjMXBUUWxWamJsWjZaRU5DVkZwWVNqSmhWMDVzWTNwRmJFMURUVWRCTVZWRlFYaE5ZMUl5T1haYU1uaHNTVVZzZFdSSFZubGliVll3U1VWR01XUkhhSFpqYld3d1pWTkNTRTE2UVdWR2R6QjRUbnBGZVUxRVVYaE5la1UwVGtST1lVWjNNSGhQUkVWNVRVUk5kMDFFUVhkTlJFSmhUVWQzZUVONlFVcENaMDVXUWtGWlZFRnNWbFJOVWsxM1JWRlpSRlpSVVVsRVFYQkVXVmQ0Y0ZwdE9YbGliV3hvVFZKWmQwWkJXVVJXVVZGSVJFRXhUbUl6Vm5Wa1IwWndZbWxDVjJGWFZqTk5VazEzUlZGWlJGWlJVVXRFUVhCSVlqSTVibUpIVldkVFZ6VnFUVkp6ZDBkUldVUldVVkZFUkVKS2FHUklVbXhqTTFGMVdWYzFhMk50T1hCYVF6VnFZakl3ZDJkblJXbE5RVEJIUTFOeFIxTkpZak5FVVVWQ1FWRlZRVUUwU1VKRWQwRjNaMmRGUzBGdlNVSkJVVU5WYWpoM1dXOVFhWGhMWW1KV09ITm5XV2QyVFZSbVdDdGtTWE5HVkU5clowdFBiR2hVTUdrd1ltTkVSbHBMTW5KUGVFcGFNblZUVEZOV2FGbDJhWEJhVGtVelNFcFJXWFYxV1hkR2FtbDVLM2xyWm1GMFFVZFRhbEo2UmpGaU16RjFORE12TjI5SE5XcE5hRE5UTXpkaGJIZHFWV0k0UTFkcFZIaHZhWEJXVDFsM1MwdDZkVlY1YTNGRlEzUnFiR2hLTkVGclYyRkVVeXRhZUV0RmNVOWhaVGwwYmtOblpVaHNiRnBGTDA5U1oyVk5ZWGd5V0U1RGIwZzJjM0pVUlZKamEzTnFlbHBhY2tGWGVFdHpaR1oyVm5KWVRucERVamxFZUZaQlUzVkpOa3g2ZDJnNFJGTnNNa1ZQYjJ0aWMyRnVXaXNyTDBweFRXVkJRa1ptVUhkcWVYZHlZakJ3Y2tWVmVUQndZV1ZXYzNWa0t6QndaV1Y0U3k4MUswVTJhM0JaUjBzMFdrc3libXR2Vmt4MVowVTFkR0ZJY2tGcU9ETlJLMUJQWW1KMlQzcFhZMFpyY0c1V1MzbHFielpMVVVGdFdEWlhTa0ZuVFVKQlFVZHFaMmRHUjAxSlNVSlJha0ZVUW1kT1ZraFRWVVZFUkVGTFFtZG5ja0puUlVaQ1VXTkVRVlJCWkVKblRsWklVa1ZGUm1wQlZXZG9TbWhrU0ZKc1l6TlJkVmxYTld0amJUbHdXa00xYW1JeU1IZGhRVmxKUzNkWlFrSlJWVWhCVVVWRldFUkNZVTFETUVkRFEzTkhRVkZWUmtKNlFVTm9hVVp2WkVoU2QwOXBPSFpqUjNSd1RHMWtkbUl5WTNaYU0wNTVUV2s1U0ZaR1RraFRWVVpJVFhrMWFtTnVVWGRMVVZsSlMzZFpRa0pSVlVoTlFVZEhTRmRvTUdSSVFUWk1lVGwyV1ROT2QweHVRbkpoVXpWdVlqSTVia3d3WkZWVk1HUktVVlZqZWsxQ01FZEJNVlZrUkdkUlYwSkNVVWM0U1hKUmRFWlNOa05WVTJ0cGEySXpZV2x0YzIweU5tTkNWRUZOUW1kT1ZraFNUVUpCWmpoRlFXcEJRVTFDT0VkQk1WVmtTWGRSV1UxQ1lVRkdTR1pEZFVaRFlWb3pXakp6VXpORGFIUkRSRzlJTm0xbWNuQk1UVU5GUjBFeFZXUkpRVkZoVFVKbmQwUkJXVXRMZDFsQ1FrRklWMlZSU1VaQmVrRkpRbWRhYm1kUmQwSkJaMGwzVFZGWlJGWlNNR1pDUTI5M1MwUkJiVzlEVTJkSmIxbG5ZVWhTTUdORWIzWk1NazU1WWtNMWQyRXlhM1ZhTWpsMlduazVTRlpHVGtoVFZVWklUWGsxYW1OdGQzZEVVVmxLUzI5YVNXaDJZMDVCVVVWTVFsRkJSR2RuUlVKQlJpOVNlazV1UXpWRWVrSlZRblJ1YURKdWRFcE1WMFZSYURsNlJXVkdXbVpRVERsUmIydHliRUZ2V0dkcVYyZE9PSEJUVWxVeGJGWkhTWEIwZWsxNFIyaDVNeTlQVWxKYVZHRTJSREpFZVRob2RrTkVja1pKTXl0c1Exa3dNVTFNTlZFMldFNUZOVkp6TW1ReFVtbGFjRTF6ZWtRMFMxRmFUa2N6YUZvd1FrWk9VUzlqYW5KRGJVeENUMGRMYTBWVk1XUnRRVmh6UmtwWVNtbFBjakpEVGxSQ1QxUjFPVVZpVEZkb1VXWmtRMFl4WW5kNmVYVXJWelppVVZOMk9GRkVialZQWkUxVEwxQnhSVEZrUldkbGRDODJSVWxTUWpjMk1VdG1XbEVyTDBSRk5reHdNMVJ5V2xSd1QwWkVSR2RZYUN0TVowZFBjM2RvUld4cU9XTXpkbHBJUjBwdWFHcHdkRGh5YTJKcGNpOHlkVXhIWm5oc1ZsbzBTekY0TlVSU1RqQlFWVXhrT1hsUVUyMXFaeXRoYWpFcmRFaDNTVEZ0VVcxYVZsazNjWFpQTlVSbmFFOTRhRXBOUjJ4Nk5teE1hVnB0ZW05blBTSXNJazFKU1VWWVJFTkRRVEJUWjBGM1NVSkJaMGxPUVdWUGNFMUNlamhqWjFrMFVEVndWRWhVUVU1Q1oydHhhR3RwUnpsM01FSkJVWE5HUVVSQ1RVMVRRWGRJWjFsRVZsRlJURVY0WkVoaVJ6bHBXVmQ0VkdGWFpIVkpSa3AyWWpOUloxRXdSV2RNVTBKVFRXcEZWRTFDUlVkQk1WVkZRMmhOUzFJeWVIWlpiVVp6VlRKc2JtSnFSVlJOUWtWSFFURlZSVUY0VFV0U01uaDJXVzFHYzFVeWJHNWlha0ZsUm5jd2VFNTZRVEpOVkZWM1RVUkJkMDVFU21GR2R6QjVUVlJGZVUxVVZYZE5SRUYzVGtSS1lVMUdVWGhEZWtGS1FtZE9Wa0pCV1ZSQmJGWlVUVkkwZDBoQldVUldVVkZMUlhoV1NHSXlPVzVpUjFWblZraEtNV016VVdkVk1sWjVaRzFzYWxwWVRYaEtWRUZxUW1kT1ZrSkJUVlJJUldSMllqSmtjMXBUUWtwaWJsSnNZMjAxYkdSRFFrSmtXRkp2WWpOS2NHUklhMmRTZWsxM1oyZEZhVTFCTUVkRFUzRkhVMGxpTTBSUlJVSkJVVlZCUVRSSlFrUjNRWGRuWjBWTFFXOUpRa0ZSUkV0VmEzWnhTSFl2VDBwSGRXOHlia2xaWVU1V1YxaFJOVWxYYVRBeFExaGFZWG8yVkVsSVRFZHdMMnhQU2lzMk1EQXZOR2hpYmpkMmJqWkJRVUl6UkZaNlpGRlBkSE0zUnpWd1NEQnlTbTV1VDBaVlFVczNNVWMwYm5wTFRXWklRMGRWYTNOWEwyMXZibUVyV1RKbGJVcFJNazRyWVdsamQwcExaWFJRUzFKVFNXZEJkVkJQUWpaQllXaG9PRWhpTWxoUE0yZzVVbFZyTWxRd1NFNXZkVUl5Vm5wNGIwMVliR3Q1VnpkWVZWSTFiWGMyU210TVNHNUJOVEpZUkZadlVsUlhhMDUwZVRWdlEwbE9USFpIYlc1U2Mwb3hlbTkxUVhGWlIxWlJUV012TjNONUt5OUZXV2hCVEhKV1NrVkJPRXRpZEhsWUszSTRjMjUzVlRWRE1XaFZjbmRoVnpaTlYwOUJVbUU0Y1VKd1RsRmpWMVJyWVVsbGIxbDJlUzl6UjBsS1JXMXFVakIyUmtWM1NHUndNV05UWVZkSmNqWXZOR2MzTW00M1QzRllkMlpwYm5VM1dsbFhPVGRGWm05UFUxRktaVUY2UVdkTlFrRkJSMnBuWjBWNlRVbEpRa3g2UVU5Q1owNVdTRkU0UWtGbU9FVkNRVTFEUVZsWmQwaFJXVVJXVWpCc1FrSlpkMFpCV1VsTGQxbENRbEZWU0VGM1JVZERRM05IUVZGVlJrSjNUVU5OUWtsSFFURlZaRVYzUlVJdmQxRkpUVUZaUWtGbU9FTkJVVUYzU0ZGWlJGWlNNRTlDUWxsRlJraG1RM1ZHUTJGYU0xb3ljMU16UTJoMFEwUnZTRFp0Wm5Kd1RFMUNPRWRCTVZWa1NYZFJXVTFDWVVGR1NuWnBRakZrYmtoQ04wRmhaMkpsVjJKVFlVeGtMMk5IV1ZsMVRVUlZSME5EYzBkQlVWVkdRbmRGUWtKRGEzZEtla0ZzUW1kbmNrSm5SVVpDVVdOM1FWbFpXbUZJVWpCalJHOTJUREk1YW1NelFYVmpSM1J3VEcxa2RtSXlZM1phTTA1NVRXcEJlVUpuVGxaSVVqaEZTM3BCY0UxRFpXZEtZVUZxYUdsR2IyUklVbmRQYVRoMldUTktjMHh1UW5KaFV6VnVZakk1Ymt3eVpIcGpha2wyV2pOT2VVMXBOV3BqYlhkM1VIZFpSRlpTTUdkQ1JHZDNUbXBCTUVKbldtNW5VWGRDUVdkSmQwdHFRVzlDWjJkeVFtZEZSa0pSWTBOQlVsbGpZVWhTTUdOSVRUWk1lVGwzWVRKcmRWb3lPWFphZVRsNVdsaENkbU15YkRCaU0wbzFUSHBCVGtKbmEzRm9hMmxIT1hjd1FrRlJjMFpCUVU5RFFWRkZRVWhNWlVwc2RWSlVOMkoyY3pJMlozbEJXamh6YnpneGRISlZTVk5rTjA4ME5YTnJSRlZ0UVdkbE1XTnVlR2hITVZBeVkwNXRVM2hpVjNOdmFVTjBNbVYxZURsTVUwUXJVRUZxTWt4SldWSkdTRmN6TVM4MmVHOXBZekZyTkhSaVYxaHJSRU5xYVhJek4zaFVWRTV4VWtGTlVGVjVSbEpYVTJSMmRDdHViRkJ4ZDI1aU9FOWhNa2t2YldGVFNuVnJZM2hFYWs1VFpuQkVhQzlDWkRGc1drNW5aR1F2T0dOTVpITkZNeXQzZVhCMVprbzVkVmhQTVdsUmNHNW9PWHBpZFVaSmQzTkpUMDVIYkRGd00wRTRRMmQ0YTNGSkwxVkJhV2d6U21GSFQzRmpjR05rWVVOSmVtdENZVkk1ZFZsUk1WZzBhekpXWnpWQlVGSk1iM1Y2Vm5rM1lUaEpWbXMyZDNWNU5uQnRLMVEzU0ZRMFRGazRhV0pUTlVaRldteG1RVVpNVTFjNFRuZHpWbm81VTBKTE1sWnhiakZPTUZCSlRXNDFlRUUyVGxwV1l6ZHZPRE0xUkV4QlJuTm9SVmRtUXpkVVNXVXpaejA5SWwxOS5leUp1YjI1alpTSTZJaTlYVG1SVFZXOHpiRUl4ZWt0Mk5UVlpNV1EyY2psR1pXdFJkbE5rZERjNWNHaDRjMmhuTjNsMVIxazlJaXdpZEdsdFpYTjBZVzF3VFhNaU9qRTFNelUyT1Rjd056TTFOVEFzSW1Gd2ExQmhZMnRoWjJWT1lXMWxJam9pWTI5dExtZHZiMmRzWlM1aGJtUnliMmxrTG1kdGN5SXNJbUZ3YTBScFoyVnpkRk5vWVRJMU5pSTZJako1TXpBNFJ6Y3hMM2RaUmtZMk9XRnVSVzlKT1VGYWNrTmFPREZFV0dSMk1YaEhNMjg0UVZkUlNITTlJaXdpWTNSelVISnZabWxzWlUxaGRHTm9JanAwY25WbExDSmhjR3REWlhKMGFXWnBZMkYwWlVScFoyVnpkRk5vWVRJMU5pSTZXeUk0VURGelZ6QkZVRXBqYzJ4M04xVjZVbk5wV0V3Mk5IY3JUelV3UldRclVrSkpRM1JoZVRGbk1qUk5QU0pkTENKaVlYTnBZMGx1ZEdWbmNtbDBlU0k2ZEhKMVpYMC5QVW9fT0h0dW96SWUxZGZFNlctSUVlYkZtN0R0Qll6M2NmZ0UzRlB5X3dVQlFCMjUwUE1WWjNVbk1NVjYwb0Q2U3d0ajZtQ0lQYnNYZnBULXFuY184eHlTUURndXZQUmp1b191b1JtUWF4aV9FSEZVaTZrZFV0akhaNkY1bWpYcVF4LWRiaFlONU00dG01WlM2bUxaMkdlbGlVcE1UVG9nU2FQUVZiVnl1Y3g0aGpfT1VDLWVPM1lCRmRldmw0d0pmSy15QVJxaGtmOHN6NEgwa1E5TU9IT2U0N0x2a0h3RnI2MElQSjNaQ3QwSklKYnJWVDZnMHJJal9iSlo3aXFrTDFOWUhrbURvNUhnSkgyTXA3QnYtZlJfMHcydzJyWkIzZk5zVGhxRm9UbUI4RU5XUmJjQ3lWQXBncVdIbFU5bUh5SlJGWVVsbnVDcGRGSEwwUjFaX1FoYXV0aERhdGFYxTLLgNysw8NSRiywHzv-MC3m83EvMP0g7NGcO6W4WJSVRAAAAAAAAAAAAAAAAAAAAAAAAAAAAEEBKg96NvDCk5gmyyLqM0zXE0ZZnSkTarHzUfYU2PHWwdQhjjWLXayf0-jYLazWjpSr-N8DM1Zhls4jfmQCqa50X6UBAgMmIAEhWCAGD72C5VXE3mwMjzc_X0_7wUgIOA6kt2KoDIn1-1PHdSJYIAoZmBXyEJkjvlu251BDb8VoOtIketAD1VvYc3WUJJrZ'
      end

      # it do
      #   expect do
      #     subject
      #   end.not_to raise_error
      # end
      it 'TODO: handle time-dependent certificate verification error (timecop can\'t modify time in openssl world)'

      context 'when client_data_json is invalid' do
        let(:client_data_json) do
          Base64.urlsafe_encode64({
            type: "webauthn.create",
            challenge: "cmFuZG9tLXN0cmluZy1nZW5lcmF0ZWQtYnktcnAtc2VydmVy",
            origin: "https://web-authn.self-issued.app",
            androidPackageName: "com.chrome.canary.malformed"
          }.to_json, padding: false)
        end

        it do
          expect do
            subject
          end.to raise_error WebAuthn::InvalidAttestation, 'Invalid Android Safetynet Response: nonce'
        end
      end
    end
  end
end
