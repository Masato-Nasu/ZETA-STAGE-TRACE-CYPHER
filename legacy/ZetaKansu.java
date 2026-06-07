import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigDecimal;
import java.text.DecimalFormat;

public class ZetaKansu{

static int x;
static long y;
static BigDecimal sum;

public static void main(String[] args) {

	System.out.println("このプログラムはゼータ関数の値を求めるものです。");
    System.out.println("This programing is for caluculating ζ function");
    System.out.println("");
    System.out.println("最初にζ(ｎ)に、2以上10000以内の任意の自然数ｎを入れてください。");
    System.out.println("Prease enter number you wish for \"n\" ");
    BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
    try {
    	String line = reader.readLine();
    	x = Integer.parseInt(line);
    	while (x <= 1 || x > 500) {
    		System.out.println("2-500以内で入力してください。");
    		System.out.println("Prease enter number between 2-500");
    		String line2 = reader.readLine();
    		x = Integer.parseInt(line2);
    	}
    } catch (IOException e) {
    	System.out.println(e);
    } catch (NumberFormatException e) {
    	System.out.println("入力が正しくありません。");
    	System.out.println("The wrong enter");
    	System.out.println("プログラムを終了します。");
    	System.out.println("Program will exit.");
    	System.exit(0);
    }
    try {
    	System.out.println("次に精度を決めます。2以上100000000000以内の任意の自然数を、計算回数として入力してください。");
    	System.out.println("Please enter number of times for caluculating, you wish");
    	System.out.println("このプログラムでは計算回数が多いほど極限値に近似した値になります。");
    	System.out.println("Bigger number of times for caluculating will make more aculate result.");
    	String line = reader.readLine();
    	y = Long.parseLong(line);
    	while (y <= 1 || y > 100000000000L) {
    		System.out.println("2-100000000000以内で入力してください。");
    		System.out.println("Prease enter number between 2-100000000000");
    		String line2 = reader.readLine();
    		y = Long.parseLong(line2);
    	}
    } catch (IOException e) {
    	System.out.println(e);
    } catch (NumberFormatException e) {
    	System.out.println("入力が正しくありません。");
    	System.out.println("The wrong enter");
    	System.out.println("プログラムを終了します。");
    	System.out.println("Program will exit.");
    	System.exit(0);
    }
	String format = "0.000000000000000000000000000000000000000000000000000000000000"; //ここの小数点以下の0の数を変更することで、小数点以下どこまでの数値を求めるか変更できます。
	DecimalFormat decimalFormat = new DecimalFormat( format );
    sum = new BigDecimal(0);
	for (long j = 1; j < y + 1; j++) {
		BigDecimal BigDecimal1 = new BigDecimal(1);
		BigDecimal BigDecimal2 = new BigDecimal(j);
		sum = sum.add(BigDecimal1.divide((BigDecimal2.pow(x)), 60, BigDecimal.ROUND_DOWN )); //ここの数値を変更することで、小数点以下何桁目で切り捨てるかを決定できます。
	        System.out.println("Calculating result of ζ" + x + " for " + j + " times = " + decimalFormat.format(sum));
    	}
	String format2 = "0.000000000000000000000000000000000000000000000000000000000000"; //ここの小数点以下の0の数を変更することで、小数点以下どこまでの数値を答として表示するか変更できます。
	DecimalFormat decimalFormat2 = new DecimalFormat( format2 );
	System.out.println("");
    System.out.println("Final result = " + decimalFormat2.format(sum));
    System.out.println("");
    System.out.println("入力数値とそれに対応する解が、kekka.txtファイルに出力されました。");
    System.out.println("The calculate result was saved as kekka.txt");
    String kekka = "kekka.txt";
    try {
    	PrintWriter writer = new PrintWriter(new BufferedWriter(new FileWriter(kekka)));
    	writer.println("ζ" + x + "を" + y + "回計算した答えは" + decimalFormat2.format(sum) + "です。");
    	writer.println("Calculating result of " + "ζ" + x + " for " + y + " times = " + decimalFormat2.format(sum));
    	writer.println("違う入力数値でもトライしてみて下さい。");
    	writer.println("Please try with different number.");
    	writer.close();
    } catch (IOException e) {
    	System.out.println(e);
    }
    System.out.println("");
    System.out.println("プログラムを終了します。");
    System.out.println("Program will exit.");
	}
}
