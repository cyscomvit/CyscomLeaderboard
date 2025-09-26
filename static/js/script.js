function parallax_height() {
    var scroll_top = $(this).scrollTop();
    var sample_section_top = $(".sample-section").offset().top;
    var header_height = $(".sample-header-section").outerHeight();
    $(".sample-section").css({ "margin-top": header_height + 100 });
    $(".sample-header").css({ height: header_height + 100 - scroll_top });
}
parallax_height();
$(window).scroll(function () {
    parallax_height();
});
$(window).resize(function () {
    parallax_height();
});

$(document).ready(function () {
    $("#act").on("change", function () {
        console.log("changing");
        console.log(this.value);
        
        // Hide all ACT tables - dynamically based on available ACTs
        // Get all tbody elements with id starting with "act"
        $('tbody[id^="act"]').hide();
        
        // Show the selected ACT
        $(`#${this.value}`).show();
    });
});
