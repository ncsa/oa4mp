package test;

import java.net.URI;
import java.net.URLEncoder;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/7/18 at  2:45 PM
 */
public class CommandLine {
    public static void main(String[] args){
        try {
            String x = "file:///home/${group_id}/*/${username}/**";
            String x1 = URLEncoder.encode(x, "UTF-8");
            System.out.println("encoded = " + x1);
            URI uri = URI.create(x1);
           print(uri);
            uri = URI.create("scitokens:/scope?read#file:///a.b.c/foo");
            print(uri);
        }catch(Throwable t){
            t.printStackTrace();
        }
    }

    public static void print(URI uri){
        System.out.println("=====\nuri=" + uri);
        System.out.println("path=" + uri.getPath());
        System.out.println("scheme=" + uri.getScheme());
        System.out.println("authority=" + uri.getAuthority());
        System.out.println("scheme specific part=" + uri.getSchemeSpecificPart());
        System.out.println("host=" + uri.getHost());
        System.out.println("fragment=" + uri.getFragment());
        System.out.println("query=" + uri.getQuery());
        System.out.println("raw query=" + uri.getRawQuery());
        System.out.println("user info=" + uri.getUserInfo());
        System.out.println("");
    }

    public static void parse(URI uri){
        String query = uri.getQuery();
        String fragment = uri.getFragment();
        String path = uri.getPath();
        String scheme = uri.getScheme();
    }
}
