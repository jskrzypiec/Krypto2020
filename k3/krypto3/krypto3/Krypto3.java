package krypto3;

import java.awt.Color;
import java.awt.Graphics;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.imageio.ImageIO;

public class Krypto3 {
	int width;
	int height;
	int px;
	BufferedImage[] subImages;
	byte[][] bytes;
	
	public void createSubImages_array() {
		try {
			File f = new File("plain.bmp");
			BufferedImage image = ImageIO.read(f);

			this.width = image.getWidth();
			this.height = image.getHeight();
			//System.out.println(height+"x"+width);
			
			int y = this.width/this.px;
			int x = this.height/this.px;
			int elements = x*y;
			//System.out.println("blocks:"+x+"x"+y + ", elements:"+elements);
			//
			this.subImages = new BufferedImage[elements];
			//System.out.println("subImages.length:"+subImages.length);
			
			int counter = 0;
			for(int i=0; i<=image.getWidth()-this.px; i+=this.px) {
				for(int j=0; j<=image.getHeight()-this.px; j+=this.px) {
					this.subImages[counter] = image.getSubimage(i, j, this.px, this.px);
					//System.out.print(i+"x"+j + " ");
					counter++;
				}
				//System.out.println();
			}
			//System.out.println("counter:"+counter);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	public void saveSubImages_asOne(String fileName) {
		try {
			BufferedImage nowy = new BufferedImage(this.width, this.height,	BufferedImage.TYPE_INT_RGB);
			Graphics g = nowy.getGraphics();
			
			int counter = 0;
			for(int i=0; i<this.width-this.px; i+=this.px) {
				for(int j=0; j<this.height-this.px; j+=this.px) {
					g.drawImage(this.subImages[counter], i, j, null);
					counter++;
				}
			}
			File newF = new File(fileName+".bmp");
			ImageIO.write(nowy, "bmp", newF);	
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	public static void readImageBytes_toByteArray(BufferedImage img, byte[] byteArray) {
		Color black = new Color(0,0,0);
		Color white = new Color(255,255,255);
		
		for(int b=0,i=0; i<img.getHeight(); i++) {
			for(int j=0; j<img.getWidth(); j++, b++) {
				Color c = new Color(img.getRGB(i, j));
				if(c.getRGB() == black.getRGB()) {
					byteArray[b] = 1;
				}else if(c.getRGB() == white.getRGB()) {
					byteArray[b] = 0;
				}
			}
		}
	}
	
	public static void saveImageBytes_fromByteArray(BufferedImage img, byte[] byteArray) {
		Color black = new Color(0,0,0);
		Color white = new Color(255,255,255);
		
		for(int b=0,i=0; i<img.getHeight(); i++) {
			for(int j=0; j<img.getWidth(); j++, b++) {
				if(byteArray[b]==0) {
					img.setRGB(i, j, white.getRGB() );
				}else if(byteArray[b]==1) {
					img.setRGB(i, j, black.getRGB() );
				}
			}
		}
	}
	
	public static byte[] md5Cipher(byte[] byteArray, int px) {
		//cipher bytes using md5
		try {
			MessageDigest md5 = MessageDigest.getInstance("MD5");
			//System.out.println(bytes.length);
			byte[] md5Bytes = new byte[px*px];
			byte[] temp = md5.digest(byteArray);
			//md5 is 16byte long, so if block is longer than 16 - repeat md5
			for(int i=0; i<md5Bytes.length; i++) {
				int tempp = i%16;
				md5Bytes[i] = temp[tempp];
			}
			//System.out.println(md5Bytes.length);
			//System.out.println( Arrays.toString(md5Bytes) );
			for(int i=0; i<byteArray.length; i++) {
				if(md5Bytes[i]<0) {
					byteArray[i]=0;
				}else if(md5Bytes[i]>0) {
					byteArray[i]=1;
				}
			}
			//System.out.println(Arrays.toString(bytes));
			return byteArray;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	public void ecb(BufferedImage[] subImages, byte[][] bytes) {
		//for each subImage do...
		for(int m=0; m<subImages.length; m++) {
			//read subImage bytes to byteArray
			BufferedImage img = subImages[m];
			Krypto3.readImageBytes_toByteArray(img, bytes[m]);
			//System.out.println(Arrays.toString(bytes));
			
			//cipher bytes using md5
			bytes[m] = Krypto3.md5Cipher(bytes[m], this.px);
			
			//save subImage bytes from byteArray
			Krypto3.saveImageBytes_fromByteArray(img, bytes[m]);
		}
	}
	
	public void cbc(BufferedImage[] subImages, byte[][] bytes) {
		//for each subImage do...
		for(int m=0; m<subImages.length; m++) {
			BufferedImage img = subImages[m];
			Krypto3.readImageBytes_toByteArray(img, bytes[m]);
			bytes[m] = Krypto3.md5Cipher(bytes[m], this.px);
			
			//byte0 - bytes[m-1], except for the FIRST occurence
			byte[] bytes0 = new byte[this.px*this.px];
			if(m==0) {
				for(int i=0; i<bytes0.length; i++) {
					if(i%2==0) {
						bytes0[i] = 0;
					}else if(i%2==1) {
						bytes0[i] = 1;
					}
				}
			}else if(m>=1) {
				for(int i=0; i<bytes0.length; i++) {
					bytes0[i] = bytes[m-1][i];
				}
			}
			//System.out.println(Arrays.toString(bytes));
			
			//cipher bytes using XOR
			for(int i=0; i<bytes[m].length; i++) {
				bytes[m][i] = (byte)(bytes[m][i] ^ bytes0[i]);
			}
			//cipher bytes using md5
			bytes[m] = Krypto3.md5Cipher(bytes[m], this.px);
			
			//save subImage bytes from byteArray
			Krypto3.saveImageBytes_fromByteArray(img, bytes[m]);
		}
	}
	
	public void executeECB() {
		//read Image to subImages Array
		this.createSubImages_array();
		this.bytes = new byte[subImages.length][this.px*this.px]; 
		
		//ebc
		this.ecb(subImages, bytes);
		//save subImages Array as one Image
		this.saveSubImages_asOne("ecb_crypto");
	}
	
	public void executeCBC() {
		//read Image to subImages Array
		this.createSubImages_array();
		this.bytes = new byte[subImages.length][this.px*this.px]; 
				
		//cbc
		this.cbc(subImages, bytes);
		//save subImages Array as one Image
		this.saveSubImages_asOne("cbc_crypto");
	}
	
	
	public static void main(String[] args) {
		Krypto3 k3 = new Krypto3();
		k3.px = 4; // px*px - size of subImages
		
		//EBC//
		k3.executeECB();

		//CBC//
		k3.executeCBC();
	}
}
