package krypto2;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Arrays;

public class Krypto2 {
	boolean par_p = false; //-p przygotowanie pliku
	boolean par_e = false; //-e szyfrowanie
	boolean par_k = false; //-k kryptoanaliza
	
	//metoda sprawdzajaca z jakimi parametrami zostal wywolany program
	void czytajParametry(String[] args) {
		int ileArg = 0;
		for(String arg : args) {
			if(arg.charAt(0)=='-') {
				if(arg.contains("p")) {
					this.par_p = true;
					ileArg++;
				}
				if(arg.contains("e")){
					this.par_e = true;
					ileArg++;
				}
				if(arg.contains("k")){
					this.par_k = true;
					ileArg++;
				}
			}
		}
	}
	
	//funkcja przeszukujaca plik ('nazwaPliku') w poszukiwaniu poprawnych znakow (angielskie litery i spacje)
	//liczy poprawne litery; 2 parametr (ileWLinij) oznacza ile liter ma byc w jednej linicje;
	//funkcja zwaraca ilosc PE£NYCH mozliwych linii dlugosci 'ileWLinij', ktore mozna utworzyc na podstawie pliku 'nazwaPliku'
	public static int ileLinii(String nazwaPliku, int ileZnakowWLinii) {
		File f1 = new File(nazwaPliku);
		int ch;
		int ileZnakow = 0, ilePoprawnychZnakow = 0;
		int ileLinii=0;
		try {
			BufferedReader br = new BufferedReader(new FileReader(f1));
			
			while( (ch=br.read())!=-1 ) {
				ch = Character.toLowerCase(ch);
				ileZnakow++;
				if(ch==32 || (ch>=97 && ch<=122)) {
					ilePoprawnychZnakow++;
					//System.out.println("pop:|" + (char)ch + "|");
				}
			}
			ileLinii = ilePoprawnychZnakow / ileZnakowWLinii;
			//System.out.println("znaków ogólnie:" + ileZnakow);
			//System.out.println("poprawnych:" + ilePoprawnychZnakow);
			System.out.println("linie (tyle linii bedzie mial plik 'plain.txt'): " + ileLinii);
			//
			br.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return ileLinii;
	}
	
	public static void przygotujPlik(String plikZrodlowy, String plikDocelowy, int ileZnakowWLinii) {
		int ileLinii = Krypto2.ileLinii(plikZrodlowy, ileZnakowWLinii);
		File f1 = new File(plikZrodlowy);
		File f2 = new File(plikDocelowy);
		try {
			BufferedReader br = new BufferedReader(new FileReader(f1));
			BufferedWriter bw = new BufferedWriter(new FileWriter(f2));
			int ch=0;
			for(int i=0; i<ileLinii; i++) {
				String linia = "";
				for(int j=0; j<ileZnakowWLinii; j++) {
					while( ch<32 || (ch>32 && ch<97) || ch>122 ) {
						ch = br.read();
						ch = Character.toLowerCase(ch);
					}
					linia = linia + (char)ch;
					ch=0;
					//System.out.println(linia);
				}
				bw.write(linia);
				bw.newLine();
			}
			//
			br.close();
			bw.close();
			System.out.println("Przygotowano plik 'plain.txt'. Plik zawiera "+ileLinii+" linii dlugosci "+ileZnakowWLinii+" znakow kazda.\n");
		} catch (FileNotFoundException e) {
			System.out.println("(-p)BLAD! Plik 'origin.txt' nie istnieje!\n");
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	public static int[] xorLinieKluczem(String tekst, String klucz) {
		int[] wynik = new int[tekst.length()];
		byte[] tekstByte, kluczByte;
		try {
			tekstByte = new String(tekst).getBytes("UTF-8");
			kluczByte = new String(klucz).getBytes("UTF-8");
			//System.out.println(Arrays.toString(tekstByte));
			//System.out.println(Arrays.toString(kluczByte));
			int k=0;
			//tekst
			for(byte b : tekstByte) {
				//System.out.println("t["+k+"](int):"+b + "\t(byte):"+Integer.toBinaryString(b)); 
				k++;
			}
			k=0;
			//klucz
			for(byte b : kluczByte) {
				//System.out.println("k["+k+"](int):"+b + "\t(byte):"+Integer.toBinaryString(b));
				k++;
			}
			//wynik = XOR(tekst, klucz)
			for(int i=0; i<tekst.length(); i++) {
				wynik[i] = (tekstByte[i] ^ kluczByte[i]);
				//System.out.println("--w["+i+"](int):"+wynik[i] + "\t(byte):"+Integer.toBinaryString(wynik[i]));
			}
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return wynik;
	}
	
	public static int[] xorDwochLinii(int[] linia1, int[] linia2) {
		if(linia1.length == linia2.length) {
			int[] wynik = new int[linia1.length];
			for(int i=0; i<linia1.length; i++) {
				wynik[i] = linia1[i] ^ linia2[i];
			}
			return wynik;
		} else {
			return null;
		}
	}
	
	public static int xorDwochLiczb(int liczba1, int liczba2) {
		int xor = liczba1 ^ liczba2;
		return xor;
	}
	
	public static void szyfrowanieXOR(String plikZrodlowy, String plikKlucz, String plikDocelowy) {
		File f1 = new File(plikZrodlowy);
		File f2 = new File(plikKlucz);
		File f3 = new File(plikDocelowy);
		try {
			//wczytanie klucza
			BufferedReader brKey = new BufferedReader(new FileReader(f2));
			String klucz = brKey.readLine();
			brKey.close();
			System.out.println("klucz(szyfrowanie): |"+klucz+"|");
			//szyfrowanie
			BufferedReader br = new BufferedReader(new FileReader(f1));
			BufferedWriter bw = new BufferedWriter(new FileWriter(f3));
			String line;
			while( (line=br.readLine())!=null ) {
				if(line.length() == klucz.length()) {
					int[] wynik = Krypto2.xorLinieKluczem(line, klucz);
					String wynikStr = Arrays.toString(wynik);
					bw.write(wynikStr);
					bw.newLine();
				}else {
					br.close();
					bw.close();
					throw new IllegalArgumentException("(-e)BLAD! Plik nie zostal przygotowany (dlugosc klucza a dlugosci linii tekstu s¹ rozne).");
				}
			}
			br.close();
			bw.close();
			System.out.println("Zaszyfrowano tekst z pliku 'plain.txt' kluczem z pliku 'key.txt'. Wynik szyfrowania zapisano w pliku 'crypto.txt'.\n");
		} catch (FileNotFoundException e) {
			System.out.println("(-e)BLAD! Plik 'plain.txt' lub plik 'key.txt' nie istnie!\n");
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	public static void odszyfrowanieXOR(String plikZrodlowy, String plikDocelowy) {
		File f1 = new File(plikZrodlowy);
		File f2 = new File(plikDocelowy);
		try {
			//policzenie linii w plikuZrodlowym
			BufferedReader brLinie = new BufferedReader(new FileReader(f1));
			int linie = 0;
			while( brLinie.readLine()!=null ) linie++;
			brLinie.close();
			//
			int[][] tekstInt = new int[linie][];
			BufferedReader br = new BufferedReader(new FileReader(f1));
			String line;
			int i=0;
			int dlugoscLinii=20;
			while( (line=br.readLine())!=null ) {
				String[] strArr = line.replaceAll("\\[", "").replaceAll("\\]", "").replaceAll("\\s", "").split(",");
				tekstInt[i] = Krypto2.stringArr_toIntArr(strArr);
				dlugoscLinii = tekstInt[i].length;
				i++;
			}
			br.close();
			//System.out.println(dlugoscLinii);
			
			//policzenie gdzie w xorach s¹ spaje
			int[] licznik = new int[dlugoscLinii];
			for(int n=0; n<linie; n++) {
				for(int m=0; m<dlugoscLinii; m++) {
					if(tekstInt[n][m]>=64) {
						licznik[m]++;
					}
				}
			}
			//ustalenie gdzie w kluczu s¹ spacje
			int[] szukanyKlucz = new int[dlugoscLinii];
			for(int k=0; k<dlugoscLinii; k++) {
				//System.out.println("k:"+k+"="+licznik[k]);
				int x = (linie/2)+1;
				if(licznik[k] > x) {
					szukanyKlucz[k] = 32;
				}
			}
			//wyliczenie pozostalych wartosci klucza
			for(int k=0; k<dlugoscLinii; k++) {
				if(szukanyKlucz[k] != 32) {
					for(int t=0; t<linie; t++) {
						if(tekstInt[t][k]>=64) {
							//System.out.println("t:"+t + " ,k:"+k+ " ,tI:"+tekstInt[t][k]+ ", xor(tI^32):" + ( tekstInt[t][k]^32) );
							szukanyKlucz[k] = (byte)(tekstInt[t][k] ^ 32);
							break;
						}
					}
				}
			}
			
			//odszyfrowanie wiadomosci na podstawie WYLICZONEGO klucza
			char[][] odszyfrowanaWiad = new char[linie][dlugoscLinii];
			for(int n=0; n<linie; n++) {
				for(int m=0; m<dlugoscLinii; m++) {
					odszyfrowanaWiad[n][m] = (char)(tekstInt[n][m]^szukanyKlucz[m]);
				}
			}
			//zapisanie wiadomoœci do pliku
			BufferedWriter bw = new BufferedWriter(new FileWriter(f2));
			for(int n=0; n<odszyfrowanaWiad.length; n++) {
				line = new String(odszyfrowanaWiad[n]);
				bw.write(line);
				bw.newLine();
			}
			bw.close();
			System.out.println("Kryptoanaliza - wynik zapisano do pliku 'decrypt.txt'.\n");
			
		} catch (FileNotFoundException e) {
			System.out.println("BLAD! Plik 'crypto.txt' nie istnieje!\n");
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	public static int[] stringArr_toIntArr(String[] strArr) {
		int[] intArr = new int[strArr.length];
		for(int i=0; i<strArr.length; i++) {
			intArr[i] = Integer.parseInt( strArr[i] );
		}
		return intArr;
	}
	
	
	////////////////////////////////////////////////////////////////
	////////////////////////////////////////////////////////////////
	public static void main(String[] args) {
		Krypto2 k2 = new Krypto2();
		k2.czytajParametry(args);
		
		if(k2.par_p) {
			Krypto2.przygotujPlik("origin.txt", "plain.txt", 36); //36-dlugosc linii jakie chcemy uzyskac w pliku 'plain.txt'
		}
		if(k2.par_e) {
			Krypto2.szyfrowanieXOR("plain.txt", "key.txt", "crypto.txt");
		}
		if(k2.par_k) {
			Krypto2.odszyfrowanieXOR("crypto.txt", "decrypt.txt");
		}
	}

}
