$(document).ready(function() {

    $('#software tbody tr:even').addClass('zebra');
    
    $('#searchcriteria tbody tr:even').addClass('zebra');
    
	$("#search").autocomplete({
		source: "/riscos/search_autocomplete"
	});
    
	$("#searchabsolute").autocomplete({
		source: "/riscos/search_absolute_autocomplete"
	});
    
	$("#searchapp").autocomplete({
		source: "/riscos/search_app_autocomplete"
	});
    
	$("#searchbook").autocomplete({
		source: "/riscos/search_book_autocomplete"
	});
    
	$("#searchcomputer").autocomplete({
		source: "/riscos/search_computer_autocomplete"
	});
    
	$("#searchdealer").autocomplete({
		source: "/riscos/search_dealer_autocomplete"
	});
    
	$("#searchdeveloper").autocomplete({
		source: "/riscos/search_developer_autocomplete"
	});
    
    $("#searcherrormessage").autocomplete({
		source: "/riscos/search_errormessage_autocomplete"
	}); 
    
	$("#searchevent").autocomplete({
		source: "/riscos/search_event_autocomplete"
	}); 
    
	$("#searchfaq").autocomplete({
		source: "/riscos/search_faq_autocomplete"
	});    
    
	$("#searchfiletype").autocomplete({
		source: "/riscos/search_filetype_autocomplete"
	});
    
	$("#searchfont").autocomplete({
		source: "/riscos/search_font_autocomplete"
	});
    
	$("#searchforum").autocomplete({
		source: "/riscos/search_forum_autocomplete"
	});    
    
	$("#searchglossary").autocomplete({
		source: "/riscos/search_glossary_autocomplete"
	});
    
	$("#searchhowto").autocomplete({
		source: "/riscos/search_howto_autocomplete"
	});
    
	$("#searchmagazine").autocomplete({
		source: "/riscos/search_magazine_autocomplete"
	});    
    
	$("#searchmodule").autocomplete({
		source: "/riscos/search_module_autocomplete"
	});
    
	$("#searchmonitor").autocomplete({
		source: "/riscos/search_monitor_autocomplete"
	});
    
	$("#searchperipheral").autocomplete({
		source: "/riscos/search_peripheral_autocomplete"
	});
    
	$("#searchpodule").autocomplete({
		source: "/riscos/search_podule_autocomplete"
	});
    
	$("#searchproject").autocomplete({
		source: "/riscos/search_project_autocomplete"
	});
    
	$("#searchprinter").autocomplete({
		source: "/riscos/search_printer_autocomplete"
	});
    
	$("#searchservice").autocomplete({
		source: "/riscos/search_service_autocomplete"
	});
    
	$("#searchsoftwareinterrupt").autocomplete({
		source: "/riscos/search_softwareinterrupt_autocomplete"
	});
    
	$("#searchstarcommand").autocomplete({
		source: "/riscos/search_starcommand_autocomplete"
	});
    
	$("#searchusergroup").autocomplete({
		source: "/riscos/search_usergroup_autocomplete"
	});
    
	$("#searchutility").autocomplete({
		source: "/riscos/search_utility_autocomplete"
	});
    
    $("#searchvideo").autocomplete({
		source: "/riscos/search_video_autocomplete"
	});

    if ($(document).height() > $(window).height()) {
        $('#footer_container').css("position","relative");
    } else {
        $('#footer_container').css("position","fixed");
        $('#footer_container').css("bottom","0px");
    };    
    
});
