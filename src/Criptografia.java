import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class Criptografia {
    private static final String ALGORITMO = "AES/GCM/NoPadding";
    private static final int TAMANHO_SAL = 16;
    private static final int TAMANHO_IV = 12;
    private static final int BITS_CHAVE = 128;
    private static final int BITS_TAG = 128;
    private static final int ITERACOES = 600_000;

    public static String criptografar(String mensagem, String chaveDigitada)
            throws GeneralSecurityException {
        SecureRandom aleatorio = new SecureRandom();
        byte[] sal = new byte[TAMANHO_SAL];
        byte[] iv = new byte[TAMANHO_IV];
        aleatorio.nextBytes(sal);
        aleatorio.nextBytes(iv);

        SecretKeySpec chave = derivarChave(chaveDigitada, sal);
        Cipher aes = Cipher.getInstance(ALGORITMO);
        aes.init(Cipher.ENCRYPT_MODE, chave, new GCMParameterSpec(BITS_TAG, iv));
        byte[] mensagemCifrada = aes.doFinal(mensagem.getBytes(StandardCharsets.UTF_8));

        // Guardamos o sal e o IV junto dos bytes cifrados para usá-los na volta.
        byte[] resultado = ByteBuffer.allocate(sal.length + iv.length + mensagemCifrada.length)
                .put(sal)
                .put(iv)
                .put(mensagemCifrada)
                .array();

        // Base64 só representa os bytes como texto para exibição no terminal.
        return Base64.getEncoder().encodeToString(resultado);
    }

    public static String descriptografar(String textoCriptografado, String chaveDigitada)
            throws GeneralSecurityException {
        ByteBuffer dados = ByteBuffer.wrap(Base64.getDecoder().decode(textoCriptografado));
        byte[] sal = new byte[TAMANHO_SAL];
        byte[] iv = new byte[TAMANHO_IV];
        dados.get(sal);
        dados.get(iv);
        byte[] mensagemCifrada = new byte[dados.remaining()];
        dados.get(mensagemCifrada);

        // Com o mesmo texto de chave e o mesmo sal, obtemos a mesma chave AES.
        SecretKeySpec chave = derivarChave(chaveDigitada, sal);
        Cipher aes = Cipher.getInstance(ALGORITMO);
        aes.init(Cipher.DECRYPT_MODE, chave, new GCMParameterSpec(BITS_TAG, iv));
        byte[] mensagem = aes.doFinal(mensagemCifrada);
        return new String(mensagem, StandardCharsets.UTF_8);
    }

    private static SecretKeySpec derivarChave(String chaveDigitada, byte[] sal)
            throws GeneralSecurityException {
        // PBKDF2 transforma o texto digitado em uma chave AES de 128 bits.
        PBEKeySpec especificacao = new PBEKeySpec(
                chaveDigitada.toCharArray(), sal, ITERACOES, BITS_CHAVE);
        try {
            SecretKeyFactory fabrica = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] bytes = fabrica.generateSecret(especificacao).getEncoded();
            return new SecretKeySpec(bytes, "AES");
        } finally {
            especificacao.clearPassword();
        }
    }
}
