package krypto1;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.text.Normalizer;
import java.util.ArrayList;
import java.util.Scanner;


public class Krypto1 {
	//stale - nazwy uzywanych plikow
	final static String PLAIN_TEXT = "plain.txt";
	final static String CRYPTO_TEXT = "crypto.txt";
	final static String DECRYPT_TEXT = "decrypt.txt";
	final static String KEY = "key.txt";
	final static String EXTRA = "extra.txt";
	final static String KEY_FOUND = "key-found.txt";
	
	boolean par_c = false; //-c cezara
	boolean par_a = false; //-a afiniczny	
	boolean par_e = false; //-e szyfrowanie
	boolean par_d = false; //-d odszyfrowanie
	boolean par_j = false; //-j kryptoanaliza z tekstem jawnym
	boolean par_k = false; //-k kryptoanaliza wylacznie w oparciu o kryptogram
	
	
	//metoda wyliczajaca odwrotnosc liczby w pierscieniu m (modulo m) 		//a*a' = 1(mod m)
	static int wyliczOdwrotnoscModM(int a, int m) {
		a = a%m;
		for(int x=1; x<m; x++) { 
			if( (a*x)%m == 1 ) {
				return x;
			}
		}
		return -1;
	}
	
	//metoda kasujaca polskie znaki
	static String kasujPolskieZnaki(String oldLine) {
		String line = new String(oldLine);
		line = line.replaceAll("[^a-zA-Z0-9 .,]", "");	
		return line;
	}
	
	//metoda sprawdzajaca z jakimi parametrami zostal wywolany program
	void czytajParametry(String[] args) {
		int ileArg = 0;
		for(String arg : args) {
			if(arg.charAt(0)=='-') {
				if(arg.contains("c")) {
					this.par_c = true;
					ileArg++;
				}
				if(arg.contains("a")){
					this.par_a = true;
					ileArg++;
				}
				if(arg.contains("e")){
					this.par_e = true;
					ileArg++;
				}
				if(arg.contains("d")){
					this.par_d = true;
					ileArg++;
				}
				if(arg.contains("j")){
					this.par_j = true;
					ileArg++;
				}
				if(arg.contains("k")){
					this.par_k = true;
					ileArg++;
				}
			}
		}
		
		if(ileArg!=2) {
			//blad - musza byc podane 2 argumenty
			throw new IllegalArgumentException("Podaj 2 argumenty [-c,-a, -e,-d, -j,-k].");
		}
		
		if(par_c&&par_a || par_e&&par_d || par_j&&par_k) {
			//blad - zle polaczenie argumentow
			throw new IllegalArgumentException("Podano nieprawidlowa pare argumentow. Nie mozna podac argumentow w danych parach: [-ca, -ed, -jk].");
		}
		
		System.out.println("c:"+par_c);
		System.out.println("a:"+par_a);
		System.out.println("e:"+par_e);
		System.out.println("d:"+par_d);
		System.out.println("j:"+par_j);
		System.out.println("k:"+par_k +"\n");
	}
	
	static String szyfrowanieCezar(String text, int k) {
		char[] oldText = text.toCharArray();
		char[] newText = text.toCharArray();
		if(k>=1 && k<=25) {
			for(int i=0; i<oldText.length; i++) {
				if(Character.isUpperCase(oldText[i])) {
					newText[i] = (char)((int)( oldText[i]+k-65)%26 +65 ); //65-A
				}
				else if(Character.isLowerCase(oldText[i])) {
					newText[i] = (char)((int)( oldText[i]+k-97)%26 +97 ); //97-a
				}
			}
		}
		String newTextS = String.valueOf(newText);
		return newTextS;
	}
	
	static String odszyfrowanieCezar(String text, int k) {
		String newText = new String(text);
		if(k>=1 && k<=25) {
			newText = Krypto1.szyfrowanieCezar(text, 26-k);
		}
		return newText;
	}
	
	static String szyfrowanieAfiniczne(String text, int a, int b) {
		char[] oldText = text.toCharArray();
		char[] newText = text.toCharArray();
		
		BigInteger ba = BigInteger.valueOf(a);
		BigInteger bm = BigInteger.valueOf(26);
		if( ( ((ba.gcd(bm)).compareTo(BigInteger.valueOf(1)))==0 ) && a>0 ) { //jezeli NWD(a,26)==1
			for(int i=0; i<oldText.length; i++) {
				if(Character.isUpperCase(oldText[i])) {
					int wartChar = (int)( ((oldText[i]-65)*a+b)%26 );
					if( wartChar<0 ) {
						wartChar += 26;
					}
					newText[i] = (char)((int)( wartChar +65 )); //65-A
				}
				else if(Character.isLowerCase(oldText[i])) {
					int wartChar = (int)( ((oldText[i]-97)*a+b)%26 );
					if( wartChar<0 ) {
						wartChar += 26;
					}
					newText[i] = (char)((int)( wartChar +97 )); //97-a
				}
			}
		}
		String newTextS = String.valueOf(newText);
		return newTextS;
	}
	
	static String odszyfrowanieAfiniczne(String text, int a, int b) {
		char[] oldText = text.toCharArray();
		char[] newText = text.toCharArray();
		
		int a1 = Krypto1.wyliczOdwrotnoscModM(a, 26);
		//System.out.println(a + "," + a1);
		for(int i=0; i<oldText.length; i++) {
			if(Character.isUpperCase(oldText[i])) { //65-A
				int wartChar = (int)((oldText[i]-65-b)%26);
				if( wartChar<0 ) {
					wartChar += 26;
				}
				newText[i] = (char)((int)( (wartChar*a1)%26 +65 )); 
			}
			else if(Character.isLowerCase(oldText[i])) {
				int wartChar = (int)((oldText[i]-97-b)%26); //97-a
				if( wartChar<0 ) {
					wartChar += 26;
				}
				newText[i] = (char)((int)( (wartChar*a1)%26 +97 )); 
			}
		}
		String newTextS = String.valueOf(newText);
		return newTextS;
	}
	
	public static void main(String[] args) {
		Krypto1 k1 = new Krypto1();
		k1.czytajParametry(args);
		
		if(k1.par_c && k1.par_e) {
			///////////////////////////////////////////////////////////////////////////////////
			//szyfrowanie cezar////////////////////////////////////////////////////////////////
			///////////////////////////////////////////////////////////////////////////////////
			File f1 = new File(PLAIN_TEXT);
			File f2 = new File(KEY);
			//
			File f3 = new File(CRYPTO_TEXT);
			try {
				String line;
				String tmpLine;
				//zczytanie klucza
				int klucz = 0;
				BufferedReader br_key = new BufferedReader(new FileReader(f2));
				while( (line=br_key.readLine()) != null ) {
					klucz = Integer.parseInt(line);
					if(klucz<1 || klucz>25) {
						br_key.close();
						throw new IllegalArgumentException("W pliku 'key.txt' znajduje sie nieprawidlowy klucz. Klucz musi byc liczba naturalna z przedzialu [1,25]");
					}
				}
				br_key.close();
				
				BufferedReader br = new BufferedReader(new FileReader(f1));
				BufferedWriter bw = new BufferedWriter(new FileWriter(f3));
				while( (line=br.readLine()) != null ) {
					line = Krypto1.kasujPolskieZnaki(line);
					tmpLine = Krypto1.szyfrowanieCezar(line, klucz);
					bw.write(tmpLine);
					bw.newLine();
				}
				br.close();
				bw.close();
			} catch (FileNotFoundException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			} catch (NumberFormatException e) {
				System.out.println("Blad! Klucz w pliku 'key.txt' nie jest liczba naturalna.");
			}
			System.out.println("Zaszyfrowano szyfrem Cezara (do pliku 'crypto.txt')");
		}
		else if(k1.par_c && k1.par_d) {
			///////////////////////////////////////////////////////////////////////////////////
			//odszyfrowanie cezar//////////////////////////////////////////////////////////////
			///////////////////////////////////////////////////////////////////////////////////
			File f1 = new File(CRYPTO_TEXT);
			File f2 = new File(KEY);
			//
			File f3 = new File(PLAIN_TEXT);
			try {
				String line;
				String tmpLine;
				//zczytanie klucza
				int klucz = 0;
				BufferedReader br_key = new BufferedReader(new FileReader(f2));
				while( (line=br_key.readLine()) != null ) {
					klucz = Integer.parseInt(line);
					if(klucz<1 || klucz>25) {
						br_key.close();
						throw new IllegalArgumentException("W pliku 'key.txt' znajduje sie nieprawidlowy klucz. Klucz musi byc liczba naturalna z przedzialu [1,25]");
					}
				}
				br_key.close();
				
				BufferedReader br = new BufferedReader(new FileReader(f1));
				BufferedWriter bw = new BufferedWriter(new FileWriter(f3));
				while( (line=br.readLine()) != null ) {
					line = Krypto1.kasujPolskieZnaki(line);
					tmpLine = Krypto1.odszyfrowanieCezar(line, klucz);
					bw.write(tmpLine);
					bw.newLine();
				}
				br.close();
				bw.close();
				
			} catch (FileNotFoundException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			} catch (NumberFormatException e) {
				System.out.println("Blad! Klucz w pliku 'key.txt' nie jest liczba naturalna.");
			}
			System.out.println("Odszyfrowano szyfrem Cezara (do pliku 'plain.txt')");
		}
		else if(k1.par_c && k1.par_j) {
			///////////////////////////////////////////////////////////////////////////////////
			//kryptoanaliza cezar z tekstem jawnym/////////////////////////////////////////////
			///////////////////////////////////////////////////////////////////////////////////
			File f1 = new File(EXTRA);
			File f2 = new File(CRYPTO_TEXT);
			//
			File f3 = new File(DECRYPT_TEXT);
			File f4 = new File(KEY_FOUND);
			try {
				//szukanie klucza
				String line1, line2;
				int klucz = -1;
				BufferedReader br1 = new BufferedReader(new FileReader(f1));
				BufferedReader br2 = new BufferedReader(new FileReader(f2));
				
				while( (line1=br1.readLine())!=null && (line2=br2.readLine())!=null ) {
					line1 = Krypto1.kasujPolskieZnaki(line1);
					line2 = Krypto1.kasujPolskieZnaki(line2);
					for(int i=1; i<26; i++) {
						String tmpLine = Krypto1.szyfrowanieCezar(line1, i);
						if(String.valueOf(tmpLine).contentEquals(line2)) {
							klucz = i;
							break;
						}
					}
					if(klucz!=(-1)) {
						break;
					}
				}
				br1.close();
				br2.close();
				
				if(klucz==(-1)) {
					throw new IllegalArgumentException("Nie znaleziono klucza.");
				}
				
				//zapisanie odszyfrowanej wiadomosci
				String line;
				BufferedReader br = new BufferedReader(new FileReader(f2));
				BufferedWriter bw1 = new BufferedWriter(new FileWriter(f3));
				while( (line=br.readLine())!=null ) {
					line = Krypto1.odszyfrowanieCezar(line, klucz);
					bw1.write(line);
					bw1.newLine();
				}
				br.close();
				bw1.close();
				
				//zapisanie znalezionego klucza
				BufferedWriter bw4 = new BufferedWriter(new FileWriter(f4));
				bw4.write(Integer.toString(klucz));
				bw4.close();
				
			} catch (FileNotFoundException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}	
			System.out.println("Kryptoanaliza z tekstem jawnym i zaszyfrowanym dla szyfru Cezara. \nWynik kryptoanalizy zapisano do pliku 'decrypt.txt'");
			System.out.println("Znaleziony klucz zapisano do pliku 'key-found.txt'");
		}
		else if(k1.par_c && k1.par_k) {
			///////////////////////////////////////////////////////////////////////////////////
			//kryptoanaliza cezar w oparciu o kryptogram///////////////////////////////////////
			///////////////////////////////////////////////////////////////////////////////////
			File f1 = new File(CRYPTO_TEXT);
			File f2 = new File(DECRYPT_TEXT);
			try {
				String line;
				BufferedWriter bw = new BufferedWriter(new FileWriter(f2));
				for(int i=1; i<26; i++) {
					BufferedReader br = new BufferedReader(new FileReader(f1));
					bw.write( i+":");
					bw.newLine();
					while( (line=br.readLine())!=null ) {
						line = Krypto1.kasujPolskieZnaki(line);
						line = String.valueOf( Krypto1.odszyfrowanieCezar(line, i) );
						bw.write(line);
						bw.newLine();
					}
					bw.write("---");
					bw.newLine();
					br.close();
				}
				bw.close();
			} catch (FileNotFoundException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}
			System.out.println("Kryptoanaliza z tekstem zaszyfrowanym dla szyfru Cezara. \nWynik kryptoanalizy zapisano do pliku 'decrypt.txt'");
		}
		else if(k1.par_a && k1.par_e) {
			///////////////////////////////////////////////////////////////////////////////////
			//szyfrowanie afiniczne////////////////////////////////////////////////////////////
			///////////////////////////////////////////////////////////////////////////////////
			File f1 = new File(PLAIN_TEXT);
			File f2 = new File(KEY);
			//
			File f3 = new File(CRYPTO_TEXT);
			try {
				String line;
				String tmpLine;
				
				//zczytanie klucza
				int a = 0;
				int b = 0;
				ArrayList<Integer> klucz = new ArrayList<Integer>();	
				Scanner sc_key = new Scanner(f2);
				while( sc_key.hasNextInt() ) {
					klucz.add( sc_key.nextInt() );
				}
				sc_key.close();
				
				System.out.println(klucz);
				if(klucz.size()==2) { //w pliku musza byc dokladnie 2 liczby naturalne
					a = klucz.get(0);
					b = klucz.get(1);
				}
				
				BigInteger ba = BigInteger.valueOf(a);
				BigInteger bm = BigInteger.valueOf(26);
				if( ( ((ba.gcd(bm)).compareTo(BigInteger.valueOf(1)))!=0 ) || a<1 ) {	
					throw new IllegalArgumentException("W pliku 'key.txt' znajduje sie nieprawidlowy klucz (a,b). NWD[a,26] musi byc rowne 1.");
				}
				
				//szyfrowanie i zapis do pliku
				BufferedReader br = new BufferedReader(new FileReader(f1));
				BufferedWriter bw = new BufferedWriter(new FileWriter(f3));
				while( (line=br.readLine()) != null ) {
					line = Krypto1.kasujPolskieZnaki(line);
					tmpLine = Krypto1.szyfrowanieAfiniczne(line, a, b);
					bw.write(tmpLine);
					bw.newLine();
				}
				br.close();
				bw.close();

			} catch (FileNotFoundException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			} 
			System.out.println("Zaszyfrowano szyfrem Afinicznym (do pliku 'crypto.txt')");
		}
		else if(k1.par_a && k1.par_d) {
			///////////////////////////////////////////////////////////////////////////////////
			//odszyfrowanie afiniczne//////////////////////////////////////////////////////////
			///////////////////////////////////////////////////////////////////////////////////
			File f1 = new File(CRYPTO_TEXT);
			File f2 = new File(KEY);
			//
			File f3 = new File(PLAIN_TEXT);
			try {
				String line;
				String tmpLine;
				//zczytanie klucza
				int a = 0;
				int b = 0;
				ArrayList<Integer> klucz = new ArrayList<Integer>();	
				Scanner sc_key = new Scanner(f2);
				while( sc_key.hasNextInt() ) {
					klucz.add( sc_key.nextInt() );
					
				}
				sc_key.close();
				
				System.out.println(klucz);
				if(klucz.size()==2) { //w pliku musza byc dokladnie 2 liczby naturalne
					a = klucz.get(0);
					b = klucz.get(1);
				}
				
				BigInteger ba = BigInteger.valueOf(a);
				BigInteger bm = BigInteger.valueOf(26);
				if( ( ((ba.gcd(bm)).compareTo(BigInteger.valueOf(1)))!=0 ) || a<1 ) {	
					throw new IllegalArgumentException("W pliku 'key.txt' znajduje sie nieprawidlowy klucz (a,b). NWD[a,26] musi byc rowne 1.");
				}
				
				BufferedReader br = new BufferedReader(new FileReader(f1));
				BufferedWriter bw = new BufferedWriter(new FileWriter(f3));
				while( (line=br.readLine()) != null ) {
					line = Krypto1.kasujPolskieZnaki(line);
					tmpLine = Krypto1.odszyfrowanieAfiniczne(line, a, b);
					bw.write(tmpLine);
					bw.newLine();
				}
				br.close();
				bw.close();
				
			} catch (FileNotFoundException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			} 
			System.out.println("Odszyfrowano szyfrem Afinicznym (do pliku 'plain.txt')");
		}
		else if(k1.par_a && k1.par_j) {
			///////////////////////////////////////////////////////////////////////////////////
			//kryptoanaliza afiniczne z tekstem jawnym/////////////////////////////////////////
			///////////////////////////////////////////////////////////////////////////////////
			File f1 = new File(EXTRA);
			File f2 = new File(CRYPTO_TEXT);
			//
			File f3 = new File(DECRYPT_TEXT);
			File f4 = new File(KEY_FOUND);
			try {
				//szukanie klucza
				String line1, line2;
				int a = 0;
				int b = 0;
				BufferedReader br1 = new BufferedReader(new FileReader(f1));
				BufferedReader br2 = new BufferedReader(new FileReader(f2));
				
				while( (line1=br1.readLine())!=null && (line2=br2.readLine())!=null ) {
					line1 = Krypto1.kasujPolskieZnaki(line1);
					line2 = Krypto1.kasujPolskieZnaki(line2);
					int[] aa = {1, 3, 5, 7 ,9, 11, 15, 17, 19, 21, 23, 25};
					for(int i=0; i<12; i++) {
						for(int j=1; j<=26; j++) {
							String tmpLine = Krypto1.szyfrowanieAfiniczne(line1, aa[i], j);
							if(String.valueOf(tmpLine).contentEquals(line2)) {
								a = aa[i];
								b = j;
								break;
							}
						}
					}
					if(a!=0 && b!=0) {
						break;
					}
				}
				br1.close();
				br2.close();
				
				if(a==0 && b==0) {
					throw new IllegalArgumentException("Nie znaleziono klucza.");
				}
				
				//zapisanie odszyfrowanej wiadomosci
				String line;
				BufferedReader br = new BufferedReader(new FileReader(f2));
				BufferedWriter bw1 = new BufferedWriter(new FileWriter(f3));
				while( (line=br.readLine())!=null ) {
					line = Krypto1.odszyfrowanieAfiniczne(line, a, b);
					bw1.write(line);
					bw1.newLine();
				}
				br.close();
				bw1.close();
				
				//zapisanie znalezionego klucza
				BufferedWriter bw4 = new BufferedWriter(new FileWriter(f4));
				bw4.write(Integer.toString(a));
				bw4.newLine();
				bw4.write(Integer.toString(b));
				bw4.close();
				
			} catch (FileNotFoundException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}	
			System.out.println("Kryptoanaliza z tekstem jawnym i zaszyfrowanym dla szyfru Afinicznego. \nWynik kryptoanalizy zapisano do pliku 'decrypt.txt'");
			System.out.println("Znaleziony klucz zapisano do pliku 'key-found.txt'");
		}
		else if(k1.par_a && k1.par_k) {
			///////////////////////////////////////////////////////////////////////////////////
			//kryptoanaliza afiniczne w oparciu o kryptogram///////////////////////////////////
			///////////////////////////////////////////////////////////////////////////////////
			File f1 = new File(CRYPTO_TEXT);
			File f2 = new File(DECRYPT_TEXT);
			String line;
			try {
				BufferedWriter bw = new BufferedWriter(new FileWriter(f2));
				int[] aa = {1, 3, 5, 7 ,9, 11, 15, 17, 19, 21, 23, 25};
				int licznik = 1;
				for(int i=0; i<12; i++) {
					for(int j=1; j<=26; j++) {
						BufferedReader br = new BufferedReader(new FileReader(f1));
						bw.write( licznik+" (a="+aa[i]+", b="+j+"):" );
						bw.newLine();
						while( (line=br.readLine())!=null ) {
							line = Krypto1.kasujPolskieZnaki(line);
							line = String.valueOf( Krypto1.odszyfrowanieAfiniczne(line, aa[i], j) );
							bw.write(line);
							bw.newLine();
						}
						bw.write("---");
						bw.newLine();
						br.close();
						licznik++;
					}
				}
				bw.close();
				
			} catch (FileNotFoundException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}
			System.out.println("Kryptoanaliza z tekstem zaszyfrowanym dla szyfru Afinicznego. \nWynik kryptoanalizy zapisano do pliku 'decrypt.txt'");	
		}	
		//
	}
}
