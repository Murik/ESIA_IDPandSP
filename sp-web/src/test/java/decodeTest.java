import dk.itst.oiosaml.sp.UserAttribute;
import org.codehaus.jackson.JsonGenerationException;
import org.codehaus.jackson.map.ObjectMapper;

import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.Map;

/**
 * @author murik
 */
public class decodeTest {

	private String json ="{\"firstName\":\"Вася\",\"middleName\":\"Тест\",\"lastName\":\" \",\"userId\":\"9a77b20b-3653-408c-8f7e-89bf02ab27d1\",\"loginMethod\":\"PWD\",\"orgGuid\":null,\"orgName\":null,\"position\":null,\"username\":\" \",\"organizationGuid\":null,\"orgOid\":null,\"oktmoGuids\":[],\"userAuthorities\":[]}";
	private static Charset UTF_8_CHARSET = Charset.forName("UTF-8");


	private static String esia = "eyJ1cm46ZXNpYTpvcmdTaG9ydE5hbWUiOiLQntCQ0J4gJ9Cg0L7Qs9CwINC4INC60L7Qv9GL0YLQsCciLCJ1cm46bWFjZTpkaXI6YXR0cmlidXRlOnVzZXJJZCI6ImY2NDU3ODY4LWFjZmQtNDUwMC1hNmNiLTc1ZThkNWU3MDA4OSIsInVybjplc2lhOm9yZ0tQUCI6IjQ2MzIwMTAwMiIsInVybjptYWNlOmRpcjphdHRyaWJ1dGU6Zmlyc3ROYW1lIjoi0JDQtNC80LjQvSIsInVybjplc2lhOmF1dGhuTWV0aG9kIjoiUFdEIiwidXJuOmVzaWE6b3JnVHlwZSI6IkwiLCJ1cm46ZXNpYTpvcmdPaWQiOiI3YzFkMmJmMi1hNDc3LTRiNDMtYWY4YS0wNjQyNDU3ZTJiNzEiLCJ1cm46ZXNpYTpnbG9iYWxSb2xlIjoiRSIsInVybjplc2lhOnBlcnNvbkVNYWlsIjoiYWRtaW5AaGNzLmxhbml0LnJ1IiwidXJuOmVzaWE6b3JnSU5OIjoiMTMyNDU2Nzg5MCIsInVybjplc2lhOnBlcnNvbk9HUk4iOiIxMDcyMjIxMDA1NTQ0IiwidXJuOmVzaWE6b3JnQ29udGFjdHMiOiI8P3htbCB2ZXJzaW9uPVwiMS4wXCIgZW5jb2Rpbmc9XCJVVEYtOFwiIHN0YW5kYWxvbmU9XCJ5ZXNcIj8 PG9yZ0NvbnRhY3RzPjxjb250YWN0Pjxjb250YWN0VHlwZT5QSE48L2NvbnRhY3RUeXBlPjx2YWx1ZT4rNyg5NjYpNjY2NjY2NzwvdmFsdWU PHZlcmlmaWNhdGlvblN0YXR1cz5OPC92ZXJpZmljYXRpb25TdGF0dXM PC9jb250YWN0Pjxjb250YWN0Pjxjb250YWN0VHlwZT5FTUw8L2NvbnRhY3RUeXBlPjx2YWx1ZT5rYW1vbGluQGVzaWEucnU8L3ZhbHVlPjx2ZXJpZmljYXRpb25TdGF0dXM TjwvdmVyaWZpY2F0aW9uU3RhdHVzPjwvY29udGFjdD48L29yZ0NvbnRhY3RzPiIsInVybjplc2lhOm9yZ0xlZ2FsRm9ybSI6IjEyMTY1IiwidXJuOmVzaWE6bWVtYmVyT2ZHcm91cHMiOiJBRE1JTiIsInVybjptYWNlOmRpcjphdHRyaWJ1dGU6YXV0aFRva2VuIjoiZjY0NTc4NjgtYWNmZC00NTAwLWE2Y2ItNzVlOGQ1ZTcwMDg5IiwidXJuOm1hY2U6ZGlyOmF0dHJpYnV0ZTpsYXN0TmFtZSI6ItCQ0LTQvNC40L3QvtCyIiwidXJuOmVzaWE6b3JnUG9zaXRpb24iOiLQkNC00LzQuNC9IiwidXJuOmVzaWE6b3JnQWRkcmVzc2VzIjoiPD94bWwgdmVyc2lvbj1cIjEuMFwiIGVuY29kaW5nPVwiVVRGLThcIiBzdGFuZGFsb25lPVwieWVzXCI/PjxvcmdBZGRyZXNzZXM PGFkZHJlc3M PGFkZHJlc3NUeXBlPk9SR19QT1NUQUw8L2FkZHJlc3NUeXBlPjxjb250cnlDaGFyM0NvZGU UlVTPC9jb250cnlDaGFyM0NvZGU PGluZGV4PjYwMTEyMDwvaW5kZXg PHJlZ2lvbj7QktC70LDQtNC40LzQuNGA0YHQutCw0Y8g0J7QsdC70LDRgdGC0Yw8L3JlZ2lvbj48ZGlzdHJpY3Q 0J/QtdGC0YPRiNC40L3RgdC60LjQuSDQoNCw0LnQvtC9PC9kaXN0cmljdD48aG91c2U MjwvaG91c2U PGNvcnB1cz4xPC9jb3JwdXM PHN0cnVjdHVyZT4yPC9zdHJ1Y3R1cmU PGZsYXQ MzwvZmxhdD48L2FkZHJlc3M PGFkZHJlc3M PGFkZHJlc3NUeXBlPk9SR19MRUdBTDwvYWRkcmVzc1R5cGU PGNvbnRyeUNoYXIzQ29kZT5SVVM8L2NvbnRyeUNoYXIzQ29kZT48aW5kZXg MTUwMDA2PC9pbmRleD48cmVnaW9uPtCzINCR0LXQu9Cz0L7RgNC 0LQ8L3JlZ2lvbj48c3RyZWV0PtGD0Lsg0JvQtdC90LjQvdCwPC9zdHJlZXQ PGhvdXNlPjQ3PC9ob3VzZT48L2FkZHJlc3M PC9vcmdBZGRyZXNzZXM IiwidXJuOmVzaWE6dXNlck5hbWUiOiJ1b2FkbWluIiwidXJuOm1hY2U6ZGlyOmF0dHJpYnV0ZTptaWRkbGVOYW1lIjoi0JDQtNC80LjQvdC 0LLQuNGHIiwidXJuOmVzaWE6b3JnT0dSTiI6IjAwMDAwMDAwMDAwMDAwMCIsInVybjplc2lhOm9yZ05hbWUiOiLQntGC0LrRgNGL0YLQvtC1INCw0LrRhtC40L7QvdC10YDQvdC 0LUg0L7QsdGJ0LXRgdGC0LLQviAn0KDQvtCz0LAg0Lgg0LrQvtC/0YvRgtCwJyJ9";

	public static String encodeEsiaParameterString(String json){
		try {
//            return URLEncoder.encode(DatatypeConverter.printBase64Binary(json.getBytes(UTF_8_CHARSET)), "UTF-8");
			return DatatypeConverter.printBase64Binary(URLEncoder.encode(json,"UTF-8").getBytes(UTF_8_CHARSET));
//			return URLEncoder.encode(DatatypeConverter.printBase64Binary(json.getBytes()), "UTF-8");
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException(e);
		}
	}
	public static String decodeEsiaParameterString(String json){
		try {
//            return new String(DatatypeConverter.parseBase64Binary(URLDecoder.decode(json,"UTF-8")),UTF_8_CHARSET);
			return URLDecoder.decode(new String(DatatypeConverter.parseBase64Binary(json),UTF_8_CHARSET), "UTF-8");
//			return new String(DatatypeConverter.parseBase64Binary(json), UTF_8_CHARSET);
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException(e);
		}
	}


	public static void main(String[] args) throws IOException {
		Map<String, String> attrs = new HashMap<>();
		attrs.put("firstName", "Вася");
		attrs.put("middleName", "Петров");
		attrs.put("adress","<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><orgAddresses><address><addressType>ORG_POSTAL</addressType><contryChar3Code>RUS</contryChar3Code><index>601120</index><region>Владимирская Область</region><district>Петушинский Район</district><house>2</house><corpus>1</corpus><structure>2</structure><flat>3</flat></address><address><addressType>ORG_LEGAL</addressType><contryChar3Code>RUS</contryChar3Code><index>150006</index><region>г Белгород</region><street>ул Ленина</street><house>47</house></address></orgAddresses>");
		String json = new ObjectMapper().writeValueAsString(attrs);
		System.out.println(json);
		String jsonParameterString = encodeEsiaParameterString(json);
		System.out.println(jsonParameterString);
		String esiaParamsJsonRaw = decodeEsiaParameterString(jsonParameterString);
//		String esiaParamsJsonRaw = decodeEsiaParameterString(esia);
		System.out.println(esiaParamsJsonRaw);
	}
}
