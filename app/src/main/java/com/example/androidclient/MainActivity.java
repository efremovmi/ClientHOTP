package com.example.androidclient;

import androidx.appcompat.app.AppCompatActivity;

import android.annotation.SuppressLint;

import android.os.Bundle;

import android.view.Gravity;
import android.view.LayoutInflater;
import android.view.View;

import android.content.SharedPreferences;
import android.widget.TextView;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import android.content.Context;
import android.widget.Toast;


public class MainActivity extends AppCompatActivity {
    // =============================================================================================
    private TextView token_output_text_view;
    private SharedPreferences.Editor editor;
    // =============================================================================================
    private static final String PREFS_NAME = "MySecret";
    private static final String TOKEN = "token";
    private static final String SECRET_KEY = "password";


    @SuppressLint("MissingInflatedId")
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // Initialize the token, if there is one, if not, then generate the token and save it in memory
        SharedPreferences mPrefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        editor = mPrefs.edit();
        String token = mPrefs.getString(TOKEN, getResources().getString(R.string.token_output_text_default_view_text));
        token_output_text_view = findViewById(R.id.token_output_text_view);
        token_output_text_view.setText(token);
        editor.putString(TOKEN, token);

        // Initialize the secret key, if there is one, if not, then output an empty string in the secret_field field
        String secret_key = mPrefs.getString(SECRET_KEY, "");
        TextView password_output_text_view = findViewById(R.id.secret_field);
        password_output_text_view.setText(secret_key);
        editor.putString(SECRET_KEY, secret_key);

        // Save data in memory
        editor.apply();


        // Initialization of the notification that is generated if not all fields have been filled in
        Toast toastError = new Toast(getApplicationContext());
        toastError.setGravity(Gravity.TOP | Gravity.END, 0, 0);
        toastError.setDuration(Toast.LENGTH_SHORT);
        LayoutInflater inflater = getLayoutInflater();
        View layout = inflater.inflate(R.layout.toast_gen_token_error,
                findViewById(R.id.toast_gen_token_error_layout));
        toastError.setView(layout);

        // Initialization of the generate_new_token_button
        findViewById(R.id.generate_new_token_button).setOnClickListener(view -> {
            // generation of OTP for user counter and 10 digits

            // Check seed seed_field
            TextView seedField = findViewById(R.id.seed_field);
            String seedString = seedField.getText().toString();
            if (seedString.equals("")){
                toastError.show();
                return;
            }

            // Check seed seed_field
            TextView secretField = findViewById(R.id.secret_field);
            String secretString = secretField.getText().toString();
            if (secretString.equals("")){
                toastError.show();
                return;
            }

            byte[] key = new byte[0];
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.KITKAT) {
                key = secretString.getBytes(StandardCharsets.UTF_8);
            }

            String token1 = generateHOTP(key,  Long.parseLong(seedString), 10);
            editor.putString(TOKEN, token1);
            editor.apply();

            editor.putString(SECRET_KEY, secretString);
            editor.apply();

            token_output_text_view.setText(token1);
        });
    }



    /**
     This is a Java method for generating a one-time password (OTP) using the HMAC-based One-Time Password (HOTP) algorithm.

     The method uses the HmacSHA1 algorithm to compute an HMAC on the counter value using the secret key. The result is a byte array, which is then processed to generate the OTP.
     The HMAC result is a 20-byte array, but only the last 4 bits of the last byte are used as an offset. The offset is used to select a 4-byte subarray from the HMAC result, which is then converted to an integer value. The integer value is then truncated to the desired number of digits by taking the modulus of 10 raised to the power of the digits parameter. The result is then formatted as a string with leading zeros if necessary to match the desired length.
     Note that this method throws a RuntimeException if the HmacSHA1 algorithm is not available or if the key is invalid.

     The method takes three parameters:
     @param key a byte array key, which is the secret key shared between the OTP generator and the client,
     @param counter a long counter, which is a value that is incremented each time a new OTP is generated, and
     @param digits an int digits, which is the length of the OTP in digits.
     */
    public static String generateHOTP(byte[] key, long counter, int digits) {
      try {
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(key, "RAW"));
            ByteBuffer buffer = ByteBuffer.allocate(8).order(ByteOrder.BIG_ENDIAN);
            buffer.putLong(counter);
            byte[] hmac = mac.doFinal(buffer.array());
            int offset = hmac[hmac.length - 1] & 0x0f;
            int binary =
                    ((hmac[offset] & 0x7f) << 24) |
                            ((hmac[offset + 1] & 0xff) << 16) |
                            ((hmac[offset + 2] & 0xff) << 8) |
                            (hmac[offset + 3] & 0xff);
            int otp = binary % (int) Math.pow(10, digits);
            return String.format("%0" + digits + "d", otp);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }
}



