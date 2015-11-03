package com.mattprecious.fingerprintbug;

import android.app.Activity;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Bundle;
import android.os.CancellationSignal;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;
import android.widget.TextView;
import android.widget.Toast;
import java.security.KeyPairGenerator;
import javax.crypto.Cipher;

import static android.Manifest.permission.USE_FINGERPRINT;
import static android.content.pm.PackageManager.PERMISSION_GRANTED;

public class MainActivity extends Activity {

  @Override protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);

    if (checkSelfPermission(USE_FINGERPRINT) != PERMISSION_GRANTED) {
      notSupported();
      return;
    }

    try {
      KeyPairGenerator keyGenerator =
          KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");
      keyGenerator.initialize(new KeyGenParameterSpec.Builder("test",
          KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT) //
          .setBlockModes(KeyProperties.BLOCK_MODE_ECB) //
          .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1) //
          .build());

      Cipher cipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_RSA
          + "/"
          + KeyProperties.BLOCK_MODE_ECB
          + "/"
          + KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1);
      cipher.init(Cipher.ENCRYPT_MODE, keyGenerator.generateKeyPair().getPublic());

      FingerprintManager.CryptoObject crypto = new FingerprintManager.CryptoObject(cipher);
      CancellationSignal signal = new CancellationSignal();

      /*
       Calling authenticate twice should send an error to the first callback and send future events
       to the second callback. Instead, the error is sent to the second callback along with all
       future events, violating the contract of the callback.
       */
      FingerprintManager fingerprintManager = getSystemService(FingerprintManager.class);
      fingerprintManager.authenticate(crypto, signal, 0, new StrictCallback("A"), null);
      fingerprintManager.authenticate(crypto, signal, 0, new StrictCallback("B"), null);
    } catch (Exception ignored) {
      notSupported();
      return;
    }

    TextView textView = new TextView(this);
    textView.setText("Authenticate with fingerprint or wait for authentication to time out.");
    setContentView(textView);
  }

  private void notSupported() {
    Toast.makeText(this, "Device not supported for this test.", Toast.LENGTH_SHORT).show();
    finish();
  }

  private static final class StrictCallback extends FingerprintManager.AuthenticationCallback {
    private static final String TAG = "StrictCallback";

    private final String name;

    private boolean terminated;

    public StrictCallback(String name) {
      this.name = name;
    }

    @Override public void onAuthenticationError(int errorCode, CharSequence errString) {
      Log.d(TAG, name + ": " + errString);

      if (terminated) {
        throw new AssertionError(
            "onAuthenticationError called after callback has already been terminated.");
      }

      terminated = true;
    }

    @Override
    public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
      Log.d(TAG, name + ": Success.");

      if (terminated) {
        throw new AssertionError(
            "onAuthenticationSucceeded called after callback has already been terminated.");
      }

      terminated = true;
    }
  }
}
