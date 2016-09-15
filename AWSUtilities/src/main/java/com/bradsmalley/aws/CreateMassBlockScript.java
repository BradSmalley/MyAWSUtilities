package com.bradsmalley.aws;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.Reader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

public class CreateMassBlockScript 
{
	PrintWriter pw = null;
	private static List<String> whiteList = new ArrayList<String>();
	
	static {
		whiteList.add("73.208.180.97");
	}
	
    public static void main( String[] args )
    {
        CreateMassBlockScript app = new CreateMassBlockScript();
        app.parseLog();
        
    }
    
    public void parseLog() {
    	
    	Map<String, Set<String>> ipMap = new HashMap<String, Set<String>>();	
    	
        File logFile = new File("/var/log/auth.log");
        BufferedReader br = null;
        
        try {
        	
			br = new BufferedReader(new FileReader(logFile));
			String line;
			
			File script = new File("MassBlock.sh");
			if (script.exists()) {
				script.delete();
				script.createNewFile();
			}
			pw = new PrintWriter(script);
			pw.println("#!/bin/bash");
			
			while (br.ready()) {
				line = br.readLine();
				if (line.contains("Invalid user")) {
					String username = line.replaceAll(".*user\\s([\\w-\\.]+)\\sfrom\\s(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})", "$1");
					String ip = line.replaceAll(".*user\\s([\\w-\\.]+)\\sfrom\\s(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})", "$2");
					
					if (whiteList.contains(ip)) {
						System.out.println("***********************************");
						System.out.println("WHITELIST: " + ip + ": " + username);
						System.out.println("***********************************");
					} else {
						if (!ipMap.containsKey(ip)) {
							ipMap.put(ip, new TreeSet<String>());
						}
						ipMap.get(ip).add(username);
					}
				}
				
			}
			
			ipMap.forEach((k, v) -> {
				System.out.println("IP: " + k);
				
				pw.println("iptables -A INPUT -s " + k + " -j DROP");
				pw.println("iptables -A OUTPUT -d " + k + " -j DROP");
				
				v.forEach((ip) -> System.out.println(ip));
				
			});

		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			pw.println();
			pw.close();
			try {
				br.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
       
    }
    
}
