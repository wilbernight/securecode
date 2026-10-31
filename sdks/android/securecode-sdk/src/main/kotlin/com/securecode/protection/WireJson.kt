package com.securecode.protection

/**
 * Wire-format JSON: a tiny, dependency-free parser + a CANONICAL
 * serializer byte-compatible with Python's
 *
 *     json.dumps(obj, sort_keys=True, separators=(",", ":"),
 *                ensure_ascii=True)
 *
 * which is the exact byte stream the protector signs. The canonical form
 * is verified against fixed vectors in the SDK conformance tests
 * (sdks/vectors.json) — including non-ASCII (Persian/CJK) strings, DEL,
 * control characters and astral-plane (surrogate-pair) characters.
 *
 * Parsing accepts any valid JSON (the client only parses, never
 * re-canonicalizes untrusted input).
 */
internal object WireJson {

    // ---------------------------------------------------------------- parse
    /** Parse a JSON document into maps/lists/strings/longs/booleans/null.
     *  Object key order is preserved; duplicate keys: last one wins
     *  (same as Python's json.loads). */
    fun parse(text: String): Any? {
        val p = Parser(text)
        val v = p.parseValue()
        p.skipWs()
        if (!p.atEnd()) throw SecureCodeException("trailing characters after JSON value")
        return v
    }

    private class Parser(private val s: String) {
        private var i = 0

        val atEnd get() = i >= s.length

        fun skipWs() {
            while (i < s.length && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r')) i++
        }

        fun parseValue(): Any? {
            skipWs()
            if (atEnd) throw SecureCodeException("unexpected end of JSON")
            return when (s[i]) {
                '{' -> parseObject()
                '[' -> parseArray()
                '"' -> parseString()
                't' -> { expect("true"); true }
                'f' -> { expect("false"); false }
                'n' -> { expect("null"); null }
                else -> parseNumber()
            }
        }

        private fun expect(word: String) {
            if (!s.startsWith(word, i)) throw SecureCodeException("invalid JSON literal")
            i += word.length
        }

        private fun parseObject(): LinkedHashMap<String, Any?> {
            val map = LinkedHashMap<String, Any?>()
            i++ // '{'
            skipWs()
            if (!atEnd && s[i] == '}') { i++; return map }
            while (true) {
                skipWs()
                if (atEnd || s[i] != '"') throw SecureCodeException("expected JSON object key")
                val key = parseString()
                skipWs()
                if (atEnd || s[i] != ':') throw SecureCodeException("expected ':' in object")
                i++
                map[key] = parseValue()
                skipWs()
                if (atEnd) throw SecureCodeException("unterminated JSON object")
                when (s[i]) {
                    ',' -> { i++; }
                    '}' -> { i++; return map }
                    else -> throw SecureCodeException("expected ',' or '}'")
                }
            }
        }

        private fun parseArray(): ArrayList<Any?> {
            val list = ArrayList<Any?>()
            i++ // '['
            skipWs()
            if (!atEnd && s[i] == ']') { i++; return list }
            while (true) {
                list.add(parseValue())
                skipWs()
                if (atEnd) throw SecureCodeException("unterminated JSON array")
                when (s[i]) {
                    ',' -> { i++; }
                    ']' -> { i++; return list }
                    else -> throw SecureCodeException("expected ',' or ']'")
                }
            }
        }

        private fun parseString(): String {
            val sb = StringBuilder()
            i++ // '"'
            while (true) {
                if (atEnd) throw SecureCodeException("unterminated JSON string")
                when (val c = s[i]) {
                    '"' -> { i++; return sb.toString() }
                    '\\' -> {
                        i++
                        if (atEnd) throw SecureCodeException("unterminated escape")
                        when (val e = s[i]) {
                            '"' -> sb.append('"')
                            '\\' -> sb.append('\\')
                            '/' -> sb.append('/')
                            'b' -> sb.append('\b')
                            'f' -> sb.append('\u000C')
                            'n' -> sb.append('\n')
                            'r' -> sb.append('\r')
                            't' -> sb.append('\t')
                            'u' -> {
                                if (i + 4 >= s.length) throw SecureCodeException("bad \\u escape")
                                val hex = s.substring(i + 1, i + 5)
                                sb.append(hexToInt(hex).toChar())
                                i += 4
                            }
                            else -> throw SecureCodeException("invalid escape \\$e")
                        }
                        i++
                    }
                    else -> {
                        if (c.code < 0x20) throw SecureCodeException("raw control char in string")
                        sb.append(c)
                        i++
                    }
                }
            }
        }

        private fun hexToInt(hex: String): Int {
            var v = 0
            for (c in hex) {
                val d = Character.digit(c, 16)
                if (d < 0) throw SecureCodeException("bad \\u escape")
                v = (v shl 4) or d
            }
            return v
        }

        private fun parseNumber(): Any {
            val start = i
            if (!atEnd && (s[i] == '-' || s[i] == '+')) i++
            var isFloat = false
            while (!atEnd()) {
                val c = s[i]
                if (c.isDigit() && c.code < 128) i++
                else if (c == '.' || c == 'e' || c == 'E' || c == '-' || c == '+') {
                    // only inside the number; '-'/'+' only after e/E —
                    // lenient here, strict later via toLong/toDouble
                    if (c == '.' || c == 'e' || c == 'E') isFloat = true
                    i++
                } else break
            }
            val raw = s.substring(start, i)
            if (raw.isEmpty()) throw SecureCodeException("invalid JSON number")
            return if (isFloat) {
                (raw.toDoubleOrNull() ?: throw SecureCodeException("invalid JSON number"))
            } else {
                (raw.toLongOrNull() ?: (raw.toDoubleOrNull()
                ?: throw SecureCodeException("invalid JSON number")))
            }
        }
    }

    // ------------------------------------------------------------- serialize
    /** Canonical (signing) form — byte-exact Python parity. Only Map,
     *  List, String, Long/Int, Boolean and null values are supported;
     *  the wire format never contains floats. Keys sort by Unicode code
     *  point (like Python), NOT by UTF-16 unit. */
    fun canonicalBytes(value: Any?): ByteArray =
        serialize(StringBuilder(), value).toString().toByteArray(Charsets.US_ASCII)

    /** Human-readable form for local export files (indent-2 style). These
     *  files are only ever parsed (never signed) — any valid JSON works,
     *  this just keeps them diff- and e-mail-friendly like Python's
     *  json.dumps(indent=2). */
    fun prettyPrint(value: Any?): String {
        val sb = StringBuilder()
        pretty(sb, value, 0)
        return sb.toString()
    }

    private fun pretty(sb: StringBuilder, value: Any?, depth: Int) {
        val pad = "  ".repeat(depth)
        val padIn = "  ".repeat(depth + 1)
        when (value) {
            null -> sb.append("null")
            is Boolean -> sb.append(if (value) "true" else "false")
            is Int, is Long -> sb.append(value.toString())
            is String -> escapeInto(sb, value)
            is Map<*, *> -> {
                if (value.isEmpty()) { sb.append("{}"); return }
                sb.append("{\n")
                val keys = value.keys.mapNotNull { it as? String }
                    .sortedWith(::compareCodePoints)
                keys.forEachIndexed { i, k ->
                    sb.append(padIn)
                    escapeInto(sb, k)
                    sb.append(": ")
                    pretty(sb, value[k], depth + 1)
                    sb.append(if (i == keys.size - 1) "\n" else ",\n")
                }
                sb.append(pad).append('}')
            }
            is List<*> -> {
                if (value.isEmpty()) { sb.append("[]"); return }
                sb.append("[\n")
                value.forEachIndexed { i, v ->
                    sb.append(padIn)
                    pretty(sb, v, depth + 1)
                    sb.append(if (i == value.size - 1) "\n" else ",\n")
                }
                sb.append(pad).append(']')
            }
            else -> serialize(sb, value)
        }
    }

    private fun serialize(sb: StringBuilder, value: Any?): StringBuilder {
        when (value) {
            null -> sb.append("null")
            is Boolean -> sb.append(if (value) "true" else "false")
            is Int -> sb.append(value.toString())
            is Long -> sb.append(value.toString())
            is String -> escapeInto(sb, value)
            is Map<*, *> -> {
                val keys = value.keys.mapNotNull { it as? String }
                    .sortedWith(::compareCodePoints)
                sb.append('{')
                var first = true
                for (k in keys) {
                    if (!first) sb.append(',')
                    first = false
                    escapeInto(sb, k)
                    sb.append(':')
                    serialize(sb, value[k])
                }
                sb.append('}')
            }
            is List<*> -> {
                sb.append('[')
                value.forEachIndexed { i, v ->
                    if (i > 0) sb.append(',')
                    serialize(sb, v)
                }
                sb.append(']')
            }
            is Double, is Float ->
                throw SecureCodeException("floats are not part of the wire format")
            else ->
                throw SecureCodeException("unsupported wire type ${value::class.simpleName}")
        }
        return sb
    }

    /** Python json.dumps escaping with ensure_ascii=True: escape
     *  everything outside U+0020..U+007E plus '"' and '\\', using the
     *  short forms \b \t \n \f \r and lowercase-hex \uXXXX (astral
     *  characters become surrogate pairs, exactly like Python). */
    private fun escapeInto(sb: StringBuilder, s: String) {
        sb.append('"')
        for (ch in s) { // Char == UTF-16 code unit — surrogate pairs fall out naturally
            when (ch) {
                '"' -> sb.append("\\\"")
                '\\' -> sb.append("\\\\")
                '\n' -> sb.append("\\n")
                '\r' -> sb.append("\\r")
                '\t' -> sb.append("\\t")
                '\b' -> sb.append("\\b")
                '\u000C' -> sb.append("\\f")
                else -> {
                    val c = ch.code
                    if (c in 0x20..0x7E) {
                        sb.append(ch)
                    } else {
                        sb.append("\\u").append(String.format("%04x", c))
                    }
                }
            }
        }
        sb.append('"')
    }

    private fun compareCodePoints(a: String, b: String): Int {
        var ia = 0
        var ib = 0
        while (ia < a.length && ib < b.length) {
            val ca = a.codePointAt(ia)
            val cb = b.codePointAt(ib)
            if (ca != cb) return ca - cb
            ia += Character.charCount(ca)
            ib += Character.charCount(cb)
        }
        return (a.length - ia) - (b.length - ib)
    }
}
