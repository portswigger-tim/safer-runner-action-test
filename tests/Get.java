public class Get {
    public static void main(String[] a) throws Exception {
        var c = (java.net.HttpURLConnection) new java.net.URI(a[0]).toURL().openConnection();
        c.setConnectTimeout(20000); c.setReadTimeout(20000);
        System.out.println(c.getResponseCode());
    }
}
