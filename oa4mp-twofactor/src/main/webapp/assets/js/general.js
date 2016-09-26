/**
 * Reorders sibling elements in DOM tree according to specified order.
 * @param {Array} elems Sibling elements ordered according to required block order.
 */

//Global to hold nav status
var showNav;
showNav = "hide";
var clickX;
function reorderElements(elems) {
    // http://tanalin.com/en/articles/css-block-order/
    var count = elems.length;

    if (!count) {
        return;
    }

    var parent = elems[0].parentNode;

    for (var i = count - 1; i >= 0; i--) {
        parent.insertBefore(elems[i], parent.firstChild);
    }
}

// If IE8 or lower (http://tanalin.com/en/articles/ie-version-js/)
if (document.all && !document.addEventListener) {
    var blocks = [
        document.getElementById('news'),
        document.getElementById('calendar'),
        document.getElementById('buttons')
    ];

    reorderElements(blocks);
}


/*** NAV VISIBILITY TOGGLE ***/
    function menuToggle(blah, id) {
	var width = $(window).width();
	if(width <1024)
	{
      		 var e = document.getElementById(id);
		if(window.showNav == "hide") {
         		 e.style.display = 'block';
			window.showNav = "show";
		} else if (window.showNav == "show" && window.clickX == "clicked"){
			window.clickX = "";
			e.style.display = 'none';
			window.showNav = "hide";
		}
			
				
		
	}
    }

function hideNav(id, calledFrom) {
	if(window.showNav == "show"){
		var e = document.getElementById(id);
		e.style.display = 'none';
		window.showNav = "hide";
		    if(calledFrom == "thex") {
                        window.clickX = "clicked";
			window.showNav = "show";
                }

	}
	}


/*** CLEAR SEARCH TEXT ***/
function clearThis(target){ target.value= ""; }


/*** NAV HOVER CLEAR ***/
$(document).ready(function(){
	$("#nav > li:not(#navhome, #search, .highlight)").hover(function () {
		$("#nav .highlight > ul").css("display","none");
                },
	function () {
		$("#nav .highlight > ul").css("display","block");
	});
});

