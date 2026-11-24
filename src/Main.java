import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.NoSuchElementException;
import java.util.Scanner;

public class Main {
    public static void main(String[] args) {
        try (Scanner teclado = new Scanner(System.in)) {
            mostrarMenu(teclado);
        } catch (NoSuchElementException e) {
            System.out.println("\nEntrada encerrada.");
        } catch (GeneralSecurityException e) {
            System.out.println("Erro ao executar a operação: " + e.getMessage());
        }
    }

    private static void mostrarMenu(Scanner teclado) throws GeneralSecurityException {
        while (true) {
            System.out.println("\n=== Criptografia e Hash ===");
            System.out.println("1 - Criptografar e descriptografar (AES)");
            System.out.println("2 - Gerar e comparar hashes (SHA-256)");
            System.out.println("0 - Sair");
            System.out.print("Escolha uma opção: ");

            switch (teclado.nextLine().trim()) {
                case "1":
                    demonstrarCriptografia(teclado);
                    break;
                case "2":
                    compararHashes(teclado);
                    break;
                case "0":
                    return;
                default:
                    System.out.println("Opção inválida. Tente novamente.");
            }
        }
    }

    private static void demonstrarCriptografia(Scanner teclado)
            throws GeneralSecurityException {
        System.out.print("Digite a mensagem: ");
        String mensagem = teclado.nextLine();

        String chaveDigitada;
        do {
            System.out.print("Digite uma chave (texto não vazio): ");
            chaveDigitada = teclado.nextLine();
        } while (chaveDigitada.isBlank());

        String textoCriptografado = Criptografia.criptografar(mensagem, chaveDigitada);
        System.out.println("Texto original: " + mensagem);
        System.out.println("Texto criptografado (Base64): " + textoCriptografado);

        String textoRecuperado = Criptografia.descriptografar(textoCriptografado, chaveDigitada);
        System.out.println("Texto descriptografado: " + textoRecuperado);
        System.out.println("Mensagem original recuperada? "
                + (mensagem.equals(textoRecuperado) ? "Sim" : "Não"));
    }

    private static void compararHashes(Scanner teclado) throws GeneralSecurityException {
        System.out.print("Digite a primeira mensagem: ");
        String primeiroHash = gerarHash(teclado.nextLine());
        System.out.println("Hash da primeira mensagem: " + primeiroHash);

        System.out.print("Digite a segunda mensagem: ");
        String segundoHash = gerarHash(teclado.nextLine());
        System.out.println("Hash da segunda mensagem: " + segundoHash);

        System.out.println(primeiroHash.equals(segundoHash)
                ? "Os hashes são iguais." : "Os hashes são diferentes.");
    }

    private static String gerarHash(String mensagem) throws GeneralSecurityException {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");

        // O SHA-256 gera 32 bytes. Em hexadecimal, cada byte ocupa dois caracteres.
        byte[] hash = sha256.digest(mensagem.getBytes(StandardCharsets.UTF_8));
        return HexFormat.of().formatHex(hash);
    }
}
