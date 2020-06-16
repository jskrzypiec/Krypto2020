package krypto4;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
//import java.util.Arrays;


public class Krypto4 {
	public Krypto4() {}
	
	//takes a 'hexadecimal' String as a parameter
	//returns 'binary' (4* longer than 'hexadecimal' parameter)
	public static String hexToBinary(String hex) {
		String bin = new String(hex);
		bin = bin.replaceAll("0", "0000");
		bin = bin.replaceAll("1", "0001");
		bin = bin.replaceAll("2", "0010");
		bin = bin.replaceAll("3", "0011");
		bin = bin.replaceAll("4", "0100");
		bin = bin.replaceAll("5", "0101");
		bin = bin.replaceAll("6", "0110");
		bin = bin.replaceAll("7", "0111");
		bin = bin.replaceAll("8", "1000");
		bin = bin.replaceAll("9", "1001");
		bin = bin.replaceAll("A", "1010");
		bin = bin.replaceAll("a", "1010");
		bin = bin.replaceAll("B", "1011");
		bin = bin.replaceAll("b", "1011");
		bin = bin.replaceAll("C", "1100");
		bin = bin.replaceAll("c", "1100");
		bin = bin.replaceAll("D", "1101");
		bin = bin.replaceAll("d", "1101");
		bin = bin.replaceAll("E", "1110");
		bin = bin.replaceAll("e", "1110");
		bin = bin.replaceAll("F", "1111");
		bin = bin.replaceAll("f", "1111");
		return bin;
	}
	
	//returns String array of commands used to generate hashes
	public static String[] giveCommandArray() {
		String cmdArr[] = new String[12];
		cmdArr[0] = "cat hash.pdf personal.txt | md5sum";
		cmdArr[1] = "cat hash.pdf personal_.txt | md5sum";
		cmdArr[2] = "cat hash.pdf personal.txt | sha1sum";
		cmdArr[3] = "cat hash.pdf personal_.txt | sha1sum";
		cmdArr[4] = "cat hash.pdf personal.txt | sha224sum";
		cmdArr[5] = "cat hash.pdf personal_.txt | sha224sum";
		cmdArr[6] = "cat hash.pdf personal.txt | sha256sum";
		cmdArr[7] = "cat hash.pdf personal_.txt | sha256sum";
		cmdArr[8] = "cat hash.pdf personal.txt | sha384sum";
		cmdArr[9] = "cat hash.pdf personal_.txt | sha384sum";
		cmdArr[10] = "cat hash.pdf personal.txt | sha512sum";
		cmdArr[11] = "cat hash.pdf personal_.txt | sha512sum";
		return cmdArr;
	}
	
	//counts number of lines in file 'f'
	//returns the number of lines
	public static int countFileLines(File f) {
		int lineCount = 0;
		try {
			BufferedReader br = new BufferedReader(new FileReader(f));
			String line;
			while( (line=br.readLine()) != null ) {
				lineCount++;
			}
			br.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return lineCount;
	}
	
	//reads file, from each line takes hexadecimal hash (first word) and saves it to String Array 'strArr'
	//returns String array of hexadecimal hashes
	public static String[] readFileToStringArray(File f, int size) {
		String[] strArr = new String[size];
		try {
			BufferedReader br = new BufferedReader(new FileReader(f));
			String line;
			int i = 0;
			while( (line=br.readLine()) != null ) {
				strArr[i] = line.split("\\s")[0];
				//strArr[i] = Krypto4.hexToBinary(strArr[i]);
				i++;
			}
			br.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return strArr;
	}
	
	//takes String array of hexadecimal hasehs
	//convert each hexadecimal String to binary String using 'Krypto4.hexToBinary(...)'
	//returns String array of binary hashes
	public static String[] hexaStrArr_toBinaryStrArr(String[] hexStrArr) {
		String[] binStrArr = new String[hexStrArr.length];
		for(int i=0; i<hexStrArr.length; i++) {
			binStrArr[i] = Krypto4.hexToBinary(hexStrArr[i]);
		}
		return binStrArr;
	}
	
	//takes pairs from 'binaryArr' and compares how many BITS are different
	//diffArr[N] represents number of different bits between 'binaryArr[N]' and 'binaryArr[N+1]'
	//diffArr[N+1] represents total number of bits ('binaryArr[N]' and 'binaryArr[N+1]' size)
	public static int[] diff(String[] binaryArr, int size) {
		int[] diffArr = new int[size];
		for(int i=0; i<size; i+=2) {
			int diff = 0;
			int amount = binaryArr[i].length();
			for(int j=0; j<amount; j++) {
				if(binaryArr[i].charAt(j) != binaryArr[i+1].charAt(j)) {
					diff++;
				}
			}
			diffArr[i] = diff;
			diffArr[i+1] = amount;
		}
		return diffArr;
	}
	
	//based on 'hexaHashArr' and 'diffArr' writes results to file 'f'
	//file structure:
	//file will consist of blocks (for each checksum method)
	//a) linux command used to generate hash A
	//b) linux command used to generate hash B
	//c) 'hash A'
	//d) 'hash B'
	//e) 'The number of different bits: X out of Y, percentage: ZZ%' (in Polish language)
	//f) linebreak
	public static void writeResultsToFile(String[] hexaHashArr, int[] diffArr, File f) {
		String[] cmdArr = Krypto4.giveCommandArray();
		try {
			BufferedWriter bw = new BufferedWriter(new FileWriter(f));
			String line;
			for(int i=0; i<hexaHashArr.length; i+=2) {
				//1st command
				bw.write(cmdArr[i]);
				bw.newLine();
				
				//2nd command
				bw.write(cmdArr[i+1]);
				bw.newLine();
				
				//result of the '1st command'
				bw.write(hexaHashArr[i]);
				bw.newLine();
				
				//result of the '2nd command'
				bw.write(hexaHashArr[i+1]);
				bw.newLine();
				
				//The number of different bits
				line = "Liczba rozniacych sie bitow: "+diffArr[i]+" z "+diffArr[i+1]+", procentowo: "+(diffArr[i]*100)/diffArr[i+1]+"%.";
				bw.write(line);
				bw.newLine();
				//linebreak
				bw.newLine();
			}
			bw.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	
	
	public static void main(String[] args) {
		File f1 = new File("hash.txt");
		File f2 = new File("diff.txt");
		
		int fileLineCount = Krypto4.countFileLines(f1);
		String[] hexaHashArr = Krypto4.readFileToStringArray(f1, fileLineCount); //String array of hexadecimal hashes
		String[] binaryHashArr = Krypto4.hexaStrArr_toBinaryStrArr(hexaHashArr); //String array of binary hashes
		int[] diff = Krypto4.diff(binaryHashArr, fileLineCount);
	
		Krypto4.writeResultsToFile(hexaHashArr, diff, f2);
	}
}
