import { log } from "./logger";

var Base64 = {
	_keyStr: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",
	encode: function(e:String) {
		var t = "";
		var n, r, i, s, o, u, a;
		var f = 0;
		e = Base64._utf8_encode(e);
		while (f < e.length) {
			n = e.charCodeAt(f++);
			r = e.charCodeAt(f++);
			i = e.charCodeAt(f++);
			s = n >> 2;
			o = (n & 3) << 4 | r >> 4;
			u = (r & 15) << 2 | i >> 6;
			a = i & 63;
			if (isNaN(r)) {
				u = a = 64
			} else if (isNaN(i)) {
				a = 64
			}
			t = t + this._keyStr.charAt(s) + this._keyStr.charAt(o) + this._keyStr.charAt(u) + this._keyStr.charAt(a)
		}
		return t
	},
	decode: function(e:String) {
		var t = "";
		var n, r, i;
		var s, o, u, a;
		var f = 0;
		e = e.replace(/[^A-Za-z0-9+/=]/g, "");
		while (f < e.length) {
			s = this._keyStr.indexOf(e.charAt(f++));
			o = this._keyStr.indexOf(e.charAt(f++));
			u = this._keyStr.indexOf(e.charAt(f++));
			a = this._keyStr.indexOf(e.charAt(f++));
			n = s << 2 | o >> 4;
			r = (o & 15) << 4 | u >> 2;
			i = (u & 3) << 6 | a;
			t = t + String.fromCharCode(n);
			if (u != 64) {
				t = t + String.fromCharCode(r)
			}
			if (a != 64) {
				t = t + String.fromCharCode(i)
			}
		}
		t = Base64._utf8_decode(t);
		return t
	},
	_utf8_encode: function(e:String) {
		e = e.replace(/rn/g, "n");
		var t = "";
		for (var n = 0; n < e.length; n++) {
			var r = e.charCodeAt(n);
			if (r < 128) {
				t += String.fromCharCode(r)
			} else if (r > 127 && r < 2048) {
				t += String.fromCharCode(r >> 6 | 192);
				t += String.fromCharCode(r & 63 | 128)
			} else {
				t += String.fromCharCode(r >> 12 | 224);
				t += String.fromCharCode(r >> 6 & 63 | 128);
				t += String.fromCharCode(r & 63 | 128)
			}
		}
		return t
	},
	_utf8_decode: function(e:String) {
		var t = "";
		var n = 0;
		let c1;
		let c2;
		let c3;
		var r = c1 = c2 = 0;
		while (n < e.length) {
			r = e.charCodeAt(n);
			if (r < 128) {
				t += String.fromCharCode(r);
				n++
			} else if (r > 191 && r < 224) {
				c2 = e.charCodeAt(n + 1);
				t += String.fromCharCode((r & 31) << 6 | c2 & 63);
				n += 2
			} else {
				c2 = e.charCodeAt(n + 1);
				c3 = e.charCodeAt(n + 2);
				t += String.fromCharCode((r & 15) << 12 | (c2 & 63) << 6 | c3 & 63);
				n += 3
			}
		}
		return t
	}
}

function writeData(key:string) {
    var ios = new File("/data/data/com.umetrip.android.msky.app/hanglvzh.txt", "a+");
    ios.write(key+"\n");
    ios.flush();
    ios.close();
}

function strToHexCharCode(str:String) {
        if(str === "")
         return "";
        var hexCharCode = [];
        for(var i = 0; i < str.length; i++) {
         hexCharCode.push((str.charCodeAt(i)).toString(16));
        }
        return hexCharCode.join(" ");
       }

var result: String | null;
var hex_string: string | null;

function scan_decrypt_key_and_hook(){
    let func_addr: any[] = [];
    Process.enumerateRanges("r--").forEach((range)=>{
        try {
            // console.log(`base: ${range.base}, size: ${range.size}`);
			/*
			new feature code
			for 7.1.3 - 7.1.?
			F0 B5 03 AF ?? B0 6E 46 ?? 1D ?? ?? ?? 60 ?? 66 ?? 48 78 44
			 */
			/*
			old one
			for ? - 7.1.2
			F0 B5 03 AF ?? B0 ?? 91 ?? 90 ?? 48 78 44 00 68 00 68 ?? 90
			 */
            Memory.scanSync(range.base, range.size, "F0 B5 03 AF ?? B0 ?? 91 ?? 90 ?? 48 78 44 00 68 00 68 ?? 90").forEach((match)=> {
                log(`match at ${match.address}, size: ${match.size}`);
                func_addr.push(match.address.add(1));
            });
        } catch (error) {

        }
    });
    if(func_addr.length != 0){
    	func_addr.map(function (item:any) {
    		log(`func_addr: ${item}`);
			Interceptor.attach(item, {
				onEnter: function(args) {
					log(`a1 onEnter: ${args[0].readCString()}`);
					this.a2 = args[1];
				},
				onLeave: function(retval) {
					log(`a2 onLeave: ${this.a2.readCString()}`);
					result = Base64.decode(this.a2.readCString()+'==');
					if (result.length === 16) {
						log(`RC4 Key: ${result}`);
						writeData("RC4 Key:"+result);
						hex_string = strToHexCharCode(result)
						scan_aes_key(hex_string);

					}


				}
			});

		})

    }



}

function scan_aes_key(hex:string) {
	Process.enumerateRanges('r--').forEach(function (range) {

		try {
			// console.log("base:", range.base, "size:", range.size);
			if (hex != null) {
				// console.log("hex_string: ", hex);
				Memory.scanSync(range.base, range.size, hex).forEach(function (match) {
					log(`Memory.scan() found match at ${match.address} with size ${match.size}`);
					// console.log("AES Key:",match.address.sub(100).add(76).readCString());
					if (match.address.sub(100).add(76).readCString()?.length === 16) {
						log(`AES Key: ${match.address.sub(100).add(76).readCString()}`);
						writeData("AES Key:"+match.address.sub(100).add(76).readCString());

					}

				});
			}


		} catch (e) {

		}
	});


}

function hook_dlopen(addr: NativePointer){
    console.log(`hook dlopen: ${addr}`);
    var need_hook = false;
    const soName = 'libumejni.so';
    Interceptor.attach(addr, {
        onEnter: (args) => {
            // log(`load: ${args[0].readUtf8String()}`);
            if(args[0].readUtf8String()?.indexOf(soName) != -1){
                need_hook = true;
            }
        },
        onLeave: (retval) => {
            if(need_hook){
                scan_decrypt_key_and_hook();
                need_hook = false;
            }
        }
    });
}

const dlopen = Module.findExportByName(null, "dlopen");
const dlopen_new = Module.findExportByName(null, "android_dlopen_ext");
if(dlopen != null){
    hook_dlopen(dlopen);
}
if(dlopen_new != null){
    hook_dlopen(dlopen_new);
}
