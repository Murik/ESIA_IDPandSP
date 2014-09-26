(function(b){var a=function(){var x;
var B=function(){var c=$("<object type='application/x-ifcplugin'></object>");
$("body").append(c);
var e=c.get(0);
if(e.valid){if(e.create()==0){x=e
}else{c.remove();
throw"ds_plugin_internal"
}}else{c.remove();
throw"ds_plugin_not_found"
}};
var k=function(f){var c=f.split(" ");
return new Date(c[0]+" "+c[1]+" "+c[3]+" "+c[2]+" "+c[4])
};
var d=function(h){var c=h.getUTCDate();
var i=h.getUTCMonth()+1;
var f=h.getUTCFullYear();
return(c>9?c:"0"+c)+"."+(i>9?i:"0"+i)+"."+f
};
var q=function(c){switch(c.type){case"capi":return c.alias;
case"pkcs11":return c.alias+"/"+c.num;
default:return c.crypto_id
}};
var C=function(l){var f={};
var o=l.split("\n");
for(var h=0;
h<o.length;
h++){var c=o[h].split("=");
f[$.trim(c[0]).toLocaleLowerCase()]=$.trim(c[1])
}return f
};
var j=function(c){var e=[];
x.info_x509(x.load_x509_from_container(c),1,e);
if(x.get_last_error()!=0){throw"ds_plugin_internal"
}return e.info
};
var A=function(n,i){var h={validity:{},issuer:{},subject:{},sort:{},filter:{}};
var c=C(n.cert_subject);
var l=C(n.cert_issuer);
h.id=q(i)+"/"+n.id;
h.serial_number=n.cert_sn;
h.validity["from"]=d(k(n.cert_valid_from));
h.validity["to"]=d(k(n.cert_valid_to));
h.issuer["common_name"]=l.commonname!=undefined?l.commonname:l.cn;
h.subject["common_name"]=c.commonname!=undefined?c.commonname:c.cn;
h.subject["sn"]=c.surname!=undefined&&c.surname!=null?c.surname:"";
h.subject["gn"]=c.givenname!=undefined&&c.givenname!=null?c.givenname:"";
h.string=j(h.id);
h.type=h.subject["sn"].length>0?"extended":"base";
h.sort["from"]=k(n.cert_valid_from);
h.filter["to"]=k(n.cert_valid_to);
h.filter["csp_type"]=i.type;
if(h.issuer["common_name"]!=undefined&&h.issuer["common_name"]){h.issuer["common_name"]=h.issuer["common_name"].replace("_"," ")
}if(h.subject["common_name"]!=undefined&&h.subject["common_name"]){h.subject["common_name"]=h.subject["common_name"].replace("_"," ")
}if(h.subject["sn"]!=undefined&&h.subject["sn"]){h.subject["sn"]=h.subject["sn"].replace("_"," ")
}if(h.subject["gn"]!=undefined&&h.subject["gn"]){h.subject["gn"]=h.subject["gn"].replace("_"," ")
}return h
};
var z=function(){return x.version
};
var w=function(){var h=[];
var E=x.get_list_info_size();
if(x.get_last_error()!=0){throw"ds_plugin_internal"
}for(var p=0;
p<E;
p++){var i=[];
x.get_list_info(p,i);
if(x.get_last_error()!=0){throw"ds_plugin_internal"
}var D=q(i);
var e=x.get_list_certs_size(D);
if(x.get_last_error()!=0){throw"ds_plugin_internal"
}for(var u=0;
u<e;
u++){var c=[];
x.get_list_certs(u,c);
if(x.get_last_error()!=0){throw"ds_plugin_internal"
}h.push(A(c,i))
}}h.sort(function(l,f){return l.sort.from<f.sort.from?1:l.sort.from>f.sort.from?-1:0
});
return $(h).filter(function(){return this.filter.to>=new Date
})
};
var m=function(f){var c=w();
for(var h=0;
h<c.length;
h++){if(c[h].id==f){return c[h]
}}throw"ds_plugin_container_not_found"
};
var y=function(c){if(c.indexOf("CryptoPro")>=0||c.indexOf("VIPNet")>=0){return c.substring(0,c.indexOf("/"))
}else{return c.substring(0,c.lastIndexOf("/"))
}};
var v=function(c){var i=y(c);
var f=x.get_list_info_size();
if(x.get_last_error()!=0){throw"ds_plugin_internal"
}for(var e=0;
e<f;
e++){var h=[];
x.get_list_info(e,h);
if(x.get_last_error()!=0){throw"ds_plugin_internal"
}if(i==q(h)){return h.type=="pkcs11"
}}throw"ds_plugin_container_not_found"
};
var g=function(e,h,f){var c=[];
x.sign(e,h,{data:f},1,1,1,3,c);
switch(x.get_last_error()){case 0:return c.sign_base64;
break;
case 1:throw"ds_plugin_process_interrupted";
break;
case 25:throw"ds_plugin_container_not_found";
break;
case 160:throw"ds_plugin_bad_pin";
break;
default:throw"ds_plugin_internal"
}};
return function(){if(!x){B()
}return{version:z,crts:w,crt_info:m,is_pin_required:v,sign:g}
}
}();
b.ds_widget=function(B){var x={exclude_etk:false,language:"ru"};
var E=$.extend(true,{},x,B);
var t=b.ds_widget_translate;
var A={ru:{"dsw.cnf.dlg.select.opt.title":"Выбор сертификата ключа проверки электронной подписи","dsw.cnf.dlg.select.opt.close":"Закрыть","dsw.cnf.dlg.select.tmp.body.btn.cancel":"Отмена","dsw.cnf.dlg.select.tmp.item.issuer":"Издатель:","dsw.cnf.dlg.select.tmp.item.subject":"Кому выдан:","dsw.cnf.dlg.select.tmp.item.validity":"Действителен:","dsw.cnf.dlg.select.tmp.item.validity_from":"с","dsw.cnf.dlg.select.tmp.item.validity_to":"по","dsw.cnf.dlg.select.tmp.empty.crt_not_found":"У вас нет действующих сертификатов.","dsw.cnf.dlg.pin.opt.title":"Ввод пин-кода","dsw.cnf.dlg.pin.opt.close":"Закрыть","dsw.cnf.dlg.pin.bad_pin":"Неправильный пин-код. Осталось попыток:","dsw.cnf.dlg.pin.tmp.title":"Введите пин-код для своего сертификата электронной подписи:","dsw.cnf.dlg.pin.tmp.issuer":"Издатель:","dsw.cnf.dlg.pin.tmp.subject":"Кому выдан:","dsw.cnf.dlg.pin.tmp.validity":"Действителен:","dsw.cnf.dlg.pin.tmp.validity_from":"с","dsw.cnf.dlg.pin.tmp.validity_to":"по","dsw.cnf.dlg.pin.tmp.pin_input_label":"Пин-код","dsw.cnf.dlg.pin.tmp.btn.continue":"Продолжить","dsw.cnf.dlg.pin.tmp.btn.cancel":"Отмена","dsw.cnf.dlg.nf.opt.title":"Ошибка: не установлен плагин","dsw.cnf.dlg.nf.opt.close":"Закрыть","dsw.cnf.dlg.nf.tmp.step_list_title":"Для входа с&nbsp;помощью электронной подписи или УЭК необходимо:","dsw.cnf.dlg.nf.tmp.step_a":"Установить специальную программу&nbsp;&mdash; плагин для работы с&nbsp;электронной подписью на&nbsp;Портале государственных услуг. Для этого нажмите на&nbsp;ссылку <a href='https://esia.gosuslugi.ru/sia-web/plugin/upload/Index.spr'>Plugin для работы с электронной подписью</a>. При появлении диалогового окна с&nbsp;кнопками &laquo;Выполнить&raquo; и&nbsp;&laquo;Сохранить&raquo; выберите &laquo;Выполнить&raquo;. После установки плагина перезапустите браузер.","dsw.cnf.dlg.nf.tmp.step_b":"Для некоторых носителей электронной подписи требуется установить специальную программу&nbsp;&mdash; криптопровайдер. Для использвания УЭК установите криптопровайдер <a href='http://www.cryptopro.ru/products/fkc/kriptopro-csp-uec/getwithplugin'>КриптоПро УЭК CSP</a> (для загрузки потребуется пройти простую регистрацию).","dsw.cnf.dlg.nf.tmp.step_c":"Присоединить к&nbsp;компьютеру носитель ключа электронной подписи (USB-ключ, УЭК или смарт-карта). Должен быть вставлен только один носитель.<br />Средство электронной подписи можно получить в&nbsp;одном из&nbsp;аккредитованных Минкомсвязью России <a href='http://minsvyaz.ru/ru/directions/?regulator=118'>удостоверяющих центров</a>. УЭК можно получить в&nbsp;<a href='http://www.uecard.ru/for-citizens/how-to-get/ffc-and-uosy'>уполномоченных организациях</a> субъектов Российской Федерации.","dsw.cnf.dlg.nf.tmp.step_d":"Добавить адрес <a href='https://esia.gosuslugi.ru'>https://esia.gosuslugi.ru</a> в список надёжных узлов (только для браузера Internet Explorer). Для этого необходимо:<br/>- зайти в «Свойства обозревателя»;<br/>- выбрать закладку «Безопасность»;<br/>- выбрать зону для настройки параметров безопасности – «Надежные узлы», нажать на кнопку «Узлы»;<br/>- в поле «Добавить в зону следующий узел» ввести адрес https://esia.gosuslugi.ru, нажать «Добавить» и закрыть данное окно.","dsw.cnf.dlg.nf.tmp.btn.close":"Закрыть","dsw.cnf.dlg.old.opt.title":"Ошибка: старая версия плагина","dsw.cnf.dlg.old.opt.close":"Закрыть","dsw.cnf.dlg.old.tmp.msg_a":"У&nbsp;вас установлена старая версия плагина&nbsp;&mdash; специальной программы для работы с&nbsp;электронной подписью и&nbsp;УЭК в&nbsp;системах Электронного правительства.","dsw.cnf.dlg.old.tmp.msg_b":"Для корректной работы системы вам требуется установить новую версию.","dsw.cnf.dlg.old.tmp.msg_c":"Для этого нажмите на&nbsp;ссылку <a href='https://esia.gosuslugi.ru/sia-web/plugin/upload/Index.spr'>Plugin для работы с электронной подписью</a>.","dsw.cnf.dlg.old.tmp.msg_d":"При появлении диалогового окна с&nbsp;кнопками &laquo;Выполнить&raquo; и&nbsp;&laquo;Сохранить&raquo; &mdash;&nbsp;выберите &laquo;Выполнить&raquo;.<br />После установки плагина перезапустите браузер.","dsw.cnf.dlg.old.tmp.btn.close":"Закрыть","dsw.cnf.dlg.disclaimer.opt.title":"Обращение к средству электронной подписи","dsw.cnf.dlg.disclaimer.opt.close":"Закрыть","dsw.cnf.dlg.disclaimer.tmp.msg_a":"В&nbsp;настоящее время происходит обращение к средству электронной подписи. Этот процесс может занять около минуты.","dsw.cnf.dlg.disclaimer.tmp.msg_b":"Пожалуйста, подождите..."}};
var q=function(d){var c=E.language!=undefined&&E.language!=null?E.language:"ru";
var f=t!=undefined&&t!=null?t:A;
if(f[c]==undefined||f[c]==null){return d
}if(f[c][d]==undefined||f[c][d]==null){return d
}return f[c][d]
};
var L={dialog:{select_crt:{items_box:".datalist-block",empty_box:".content-eds",pager_box:".datalist-wrap",height_correction:".height-correction",cancel_button:"[ds-widget='cancel']",template:{body:'<div class="eds-select-dlg"><form><div class="content-eds"><div class="datalist-wrap"><div class="height-correction"><div class="datalist-block"></div></div></div></div><div class="buttons-group dialog"><button type="button" class="ui-button ui-widget ui-button-text-only button-cmd light" ds-widget="cancel"><span class="ui-button-text">'+q("dsw.cnf.dlg.select.tmp.body.btn.cancel")+"</span></button></div></form></div>",item:'<div class="datalist-item has-icon-arrow"><i class="icon-line-arrow"></i><span class="line fio"><b ds-widget="subject_common_name"></b></span><span class="line"><span class="label">'+q("dsw.cnf.dlg.select.tmp.item.issuer")+'</span>&nbsp;<span ds-widget="issuer_common_name"></span></span><span class="line" ds-widget="line_subject_sn"><span class="label">'+q("dsw.cnf.dlg.select.tmp.item.subject")+'</span>&nbsp;<span ds-widget="subject_sn"></span></span><span class="line"><span class="label">'+q("dsw.cnf.dlg.select.tmp.item.validity")+"</span>&nbsp;"+q("dsw.cnf.dlg.select.tmp.item.validity_from")+'&nbsp;<span ds-widget="validity_from"></span>&nbsp;'+q("dsw.cnf.dlg.select.tmp.item.validity_to")+'&nbsp;<span ds-widget="validity_to"></span></span></div>',empty:"<span>"+q("dsw.cnf.dlg.select.tmp.empty.crt_not_found")+"</span>"},options:{autoOpen:false,title:q("dsw.cnf.dlg.select.opt.title"),dialogClass:"dialog-edsdlg",closeText:q("dsw.cnf.dlg.select.opt.close"),modal:true,resizable:false,draggable:false},pager:{size:3,types:{base:81,extended:101},items_box:".pager-numbers",page_number_box:".pager-number",template:{body:'<div class="pager-block"><span class="pager-arrow first"><span class="pager-icon">p</span></span><span class="pager-arrow prev"><span class="pager-icon">p</span></span><span class="pager-numbers"></span><span class="pager-arrow next"><span class="pager-icon">p</span></span><span class="pager-arrow last"><span class="pager-icon">p</span></span></div>',item:'<span class="pager-number"></span>'}}},pin:{ok_button:"[ds-widget='ok']",cancel_button:"[ds-widget='cancel']",input:"[ds-widget='pin']",error_box:".ui-message-error-detail",bad_pin_text:q("dsw.cnf.dlg.pin.bad_pin"),template:'<div class="eds-pin-code-dlg"><form><div class="content-eds"><div class="eds-message"><p class="msg-title">'+q("dsw.cnf.dlg.pin.tmp.title")+'</p><div class="eds-info eds-info-pincode"><span class="line fio"><b ds-widget="subject_common_name"></b></span><span class="line"><span class="label">'+q("dsw.cnf.dlg.pin.tmp.issuer")+'</span>&nbsp;<span ds-widget="issuer_common_name"></span></span><span class="line" ds-widget="line_subject_sn"><span class="label">'+q("dsw.cnf.dlg.pin.tmp.subject")+'</span>&nbsp;<span ds-widget="subject_sn"></span></span><span class="line"><span class="label">'+q("dsw.cnf.dlg.pin.tmp.validity")+"</span>&nbsp;"+q("dsw.cnf.dlg.pin.tmp.validity_from")+'&nbsp;<span ds-widget="validity_from"></span>&nbsp;'+q("dsw.cnf.dlg.pin.tmp.validity_to")+'&nbsp;<span ds-widget="validity_to"></span></span></div></div><div class="data-form horizontal data-form-pincode"><dl><dt>'+q("dsw.cnf.dlg.pin.tmp.pin_input_label")+'</dt><dd><input type="password" class="ui-inputfield ui-inputtext ui-widget" ds-widget="pin"/><div class="field-error"><div class="ui-message-error ui-widget"><span class="ui-message-error-detail"></span></div></div></dd></dl></div></div><div class="buttons-group dialog"><button type="submit" class="ui-button ui-widget ui-button-text-icon-left button-cmd right" ds-widget="ok"><span class="ui-button-icon-left ui-icon icon-next"></span><span class="ui-button-text">'+q("dsw.cnf.dlg.pin.tmp.btn.continue")+'</span></button><button type="button" class="ui-button ui-widget ui-button-text-only button-cmd light" ds-widget="cancel"><span class="ui-button-text">'+q("dsw.cnf.dlg.pin.tmp.btn.cancel")+"</span></button></div></form></div>",options:{autoOpen:false,title:q("dsw.cnf.dlg.pin.opt.title"),dialogClass:"dialog-edsdlg",closeText:q("dsw.cnf.dlg.pin.opt.close"),modal:true,resizable:false,draggable:false}},not_found:{ok_button:"[ds-widget='ok']",template:'<div><form><div class="content-eds"><div class="eds-message"><p class="msg-title">'+q("dsw.cnf.dlg.nf.tmp.step_list_title")+'</p><ol class="list"><li>'+q("dsw.cnf.dlg.nf.tmp.step_a")+"</li><li>"+q("dsw.cnf.dlg.nf.tmp.step_b")+"</li><li>"+q("dsw.cnf.dlg.nf.tmp.step_c")+"</li><li>"+q("dsw.cnf.dlg.nf.tmp.step_d")+'</li></ol></div></div><div class="buttons-group dialog"><button type="button" class="ui-button ui-widget ui-button-text-only button-cmd" ds-widget="ok"><span class="ui-button-text">'+q("dsw.cnf.dlg.nf.tmp.btn.close")+"</span></button></div></form></div>",options:{autoOpen:false,title:q("dsw.cnf.dlg.nf.opt.title"),dialogClass:"dialog-edsdlg",closeText:q("dsw.cnf.dlg.nf.opt.close"),modal:true,resizable:false,draggable:false}},old_version:{ok_button:"[ds-widget='ok']",template:'<div><form><div class="content-eds"><div class="eds-message"><p>'+q("dsw.cnf.dlg.old.tmp.msg_a")+"</p><p>"+q("dsw.cnf.dlg.old.tmp.msg_b")+"</p><p>"+q("dsw.cnf.dlg.old.tmp.msg_c")+"</p><p>"+q("dsw.cnf.dlg.old.tmp.msg_d")+'</p></div></div><div class="buttons-group dialog"><button type="button" class="ui-button ui-widget ui-button-text-only button-cmd" ds-widget="ok"><span class="ui-button-text">'+q("dsw.cnf.dlg.old.tmp.btn.close")+"</span></button></div></form></div>",options:{autoOpen:false,title:q("dsw.cnf.dlg.old.opt.title"),dialogClass:"dialog-edsdlg",closeText:q("dsw.cnf.dlg.old.opt.close"),modal:true,resizable:false,draggable:false}},disclaimer:{delay:2000,template:'<div class="eds-select-dlg"><form><div class="content-eds"><div class="eds-process"><p class="descr">'+q("dsw.cnf.dlg.disclaimer.tmp.msg_a")+'</p><p class="wait ajax-loader-bg">'+q("dsw.cnf.dlg.disclaimer.tmp.msg_b")+"</p></div></div></form></div>",options:{autoOpen:false,title:q("dsw.cnf.dlg.disclaimer.opt.title"),dialogClass:"dialog-edsdlg",closeText:q("dsw.cnf.dlg.disclaimer.opt.close"),modal:true,resizable:false,draggable:false}}}};
var H=function(d,c){switch(d){case"ds_plugin_not_found":c({code:"plugin_not_found"});
break;
case"ds_plugin_internal":c({code:"internal"});
break;
case"ds_plugin_container_not_found":c({code:"container_not_found"});
break;
case"ds_plugin_process_interrupted":c({code:"process_interrupted"});
break;
default:throw d
}};
var D=function(c){return c!=undefined&&c!=null?"000".substring(0,3-c.length)+c:"000"
};
var J=function(f){var c=f!=undefined&&f!=null?f.split("."):[];
var g="1";
for(var d=0;
d<4;
d++){g=g+D(c[d])
}return parseInt(g)
};
var F=function(m,v,g,c){var h=false;
var w=$(L.dialog.pin.template).dialog(L.dialog.pin.options);
var d=function(i,f){w.remove();
if(h){v(w.find(L.dialog.pin.input).val())
}else{g()
}};
var p=function(f){h=true;
w.dialog("close")
};
var l=function(f){w.dialog("close")
};
w.find("[ds-widget='subject_common_name']").html(m.subject["common_name"]);
w.find("[ds-widget='issuer_common_name']").html(m.issuer["common_name"]);
w.find("[ds-widget='validity_from']").html(m.validity["from"]);
w.find("[ds-widget='validity_to']").html(m.validity["to"]);
w.find("[ds-widget='subject_sn']").html(m.type=="extended"?$.trim($.trim(m.subject["sn"])+" "+$.trim(m.subject["gn"])):"");
if(m.type!="extended"){w.find("[ds-widget='line_subject_sn']").hide()
}w.find(L.dialog.pin.error_box).text(c);
w.dialog("option","close",d);
w.find(L.dialog.pin.cancel_button).bind("click",l);
w.find(L.dialog.pin.ok_button).bind("click",p);
w.dialog("open")
};
var z=function(p,y,h){var d=-1;
var M=$(L.dialog.select_crt.template.body).dialog(L.dialog.select_crt.options);
if(E.exclude_etk){p=$(p).filter(function(){return this.filter.csp_type!="pkcs11"
})
}var g=function(f,c){M.remove();
if(d<0){h()
}else{y(d)
}};
var w=function(c){d=c.data.id;
M.dialog("close")
};
var m=function(c){M.dialog("close")
};
var i=function(f,o){M.find(L.dialog.select_crt.items_box).html("");
for(var l=f;
l<o;
l++){var c=$(L.dialog.select_crt.template.item);
c.find("[ds-widget='subject_common_name']").html(p[l]["subject"]["common_name"]);
c.find("[ds-widget='issuer_common_name']").html(p[l]["issuer"]["common_name"]);
c.find("[ds-widget='validity_from']").html(p[l]["validity"]["from"]);
c.find("[ds-widget='validity_to']").html(p[l]["validity"]["to"]);
c.find("[ds-widget='subject_sn']").html(p[l]["type"]=="extended"?$.trim($.trim(p[l]["subject"]["sn"])+" "+$.trim(p[l]["subject"]["gn"])):"");
if(p[l]["type"]!="extended"){c.find("[ds-widget='line_subject_sn']").hide()
}c.bind("click",{id:l},w);
M.find(L.dialog.select_crt.items_box).append(c)
}};
var v={current_page:1,page_size:L.dialog.select_crt.pager.size,element:$(L.dialog.select_crt.pager.template.body),max_height:0,_set_max_height:function(c){v.max_height=v.max_height<c?c:v.max_height
},_height_page:function(f){var u=0;
var o=(f-1)*v.page_size;
var c=p.length<f*v.page_size?p.length:f*v.page_size;
for(var l=o;
l<c;
l++){u=u+L.dialog.select_crt.pager.types[p[l]["type"]]
}return u+(c-o)-1
},_last_page:function(){return p.length%v.page_size>0?(p.length-p.length%v.page_size)/v.page_size+1:p.length/v.page_size
},_first:function(){v.current_page=1;
v._refresh()
},_previous:function(){v.current_page=v.current_page>1?v.current_page-1:v.current_page;
v._refresh()
},_page:function(c){v.current_page=c.data.p;
v._refresh()
},_next:function(){v.current_page=p.length>v.current_page*v.page_size?v.current_page+1:v.current_page;
v._refresh()
},_last:function(){v.current_page=v._last_page();
v._refresh()
},_refresh:function(){v.element.find(".first").removeClass("disabled").unbind("click");
v.element.find(".prev").removeClass("disabled").unbind("click");
v.element.find(".next").removeClass("disabled").unbind("click");
v.element.find(".last").removeClass("disabled").unbind("click");
v.element.find(L.dialog.select_crt.pager.page_number_box).removeClass("active");
if(v.current_page==1){v.element.find(".first").addClass("disabled");
v.element.find(".prev").addClass("disabled");
v.element.find(".next").bind("click",v._next);
v.element.find(".last").bind("click",v._last)
}if(v.current_page==v._last_page()){v.element.find(".first").bind("click",v._first);
v.element.find(".prev").bind("click",v._previous);
v.element.find(".next").addClass("disabled");
v.element.find(".last").addClass("disabled")
}if(v.current_page!=1&&v.current_page!=v._last_page()){v.element.find(".first").bind("click",v._first);
v.element.find(".prev").bind("click",v._previous);
v.element.find(".next").bind("click",v._next);
v.element.find(".last").bind("click",v._last)
}v.element.find(L.dialog.select_crt.pager.page_number_box+":eq("+(v.current_page-1)+")").addClass("active");
var c=(v.current_page-1)*v.page_size;
var f=p.length<v.current_page*v.page_size?p.length:v.current_page*v.page_size;
i(c,f)
},init:function(){for(var c=0;
c<v._last_page();
c++){var f=$(L.dialog.select_crt.pager.template.item);
f.text(c+1);
f.bind("click",{p:c+1},v._page);
v.element.find(L.dialog.select_crt.pager.items_box).append(f);
v._set_max_height(v._height_page(c+1))
}if(p.length<=v.page_size){v.element.hide()
}if(p.length>v.page_size){M.find(L.dialog.select_crt.height_correction).css("height",v.max_height)
}M.find(L.dialog.select_crt.pager_box).append(v.element);
v._refresh()
}};
M.find(L.dialog.select_crt.cancel_button).bind("click",m);
M.dialog("option","close",g);
if(p.length>0){v.init()
}else{M.find(L.dialog.select_crt.empty_box).html(L.dialog.select_crt.template.empty)
}M.dialog("open")
};
var I=function(d){var c=$(L.dialog.not_found.template).dialog(L.dialog.not_found.options);
var f=function(h,g){c.remove();
d({code:"plugin_not_found"})
};
c.dialog("option","close",f);
c.find(L.dialog.not_found.ok_button).bind("click",f);
c.dialog("open")
};
var k=function(d){var c=$(L.dialog.old_version.template).dialog(L.dialog.old_version.options);
var f=function(h,g){c.remove();
d({code:"old_version"})
};
c.dialog("option","close",f);
c.find(L.dialog.old_version.ok_button).bind("click",f);
c.dialog("open")
};
var C=function(){var d=$(L.dialog.disclaimer.template).dialog(L.dialog.disclaimer.options);
var c=function(f,g){d.remove()
};
d.dialog("option","close",c);
d.dialog("open");
return d
};
var G=function(f,g,d){var c=C();
setTimeout(function(){try{var h=a().version();
c.dialog("close");
if(J(h)>=J(d)){f({version:h})
}else{k(g)
}}catch(i){c.dialog("close");
if(i=="ds_plugin_not_found"){I(g)
}else{H(i,g)
}}},L.dialog.disclaimer.delay)
};
var e=function(d,f){var c=C();
setTimeout(function(){var h;
try{h=a().crts();
c.dialog("close")
}catch(l){c.dialog("close");
H(l,f);
return
}var m=function(){f({code:"canceled_by_user"})
};
var g=function(i){d({id:h[i].id,certificate:h[i].string})
};
z(h,g,m)
},L.dialog.disclaimer.delay)
};
var K=function(g,h,f,c){var d=C();
setTimeout(function(){var w;
try{w=a().is_pin_required(g)
}catch(n){d.dialog("close");
H(n,c);
return
}if(w){var i;
try{i=a().crt_info(g);
d.dialog("close")
}catch(n){d.dialog("close");
H(n,c);
return
}var y=function(l){if(l==null||$.trim(l).length==0){throw"ds_plugin_bad_pin"
}};
var r=0;
var s=function(){c({code:"canceled_by_user"})
};
var m=function(l){var p=C();
setTimeout(function(){try{y(l);
var v=a().sign(g,l,h);
p.dialog("close");
f({sign:v})
}catch(o){p.dialog("close");
if(o=="ds_plugin_bad_pin"){r++;
if(r<3){F(i,m,s,L.dialog.pin.bad_pin_text+" "+(3-r))
}else{c({code:"max_attempts_exceeded"})
}}else{H(o,c)
}}},L.dialog.disclaimer.delay)
};
F(i,m,s,"")
}else{d.dialog("close");
try{f({sign:a().sign(g,"",h)})
}catch(n){H(n,c)
}}},L.dialog.disclaimer.delay)
};
var j=function(d,c,f){e(function(g){K(g.id,d,function(h){h.id=g.id;
h.certificate=g.certificate;
c(h)
},function(h){f(h)
})
},function(g){f(g)
})
};
return{check_plugin:G,select:e,sign:K,select_and_sign:j}
}
})(window);