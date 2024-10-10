// helpers.js
function prettyDate(date) {
    return date.toLocaleString('en-US', { 
        year: 'numeric', 
        month: 'long', 
        day: 'numeric', 
        hour: '2-digit', 
        minute: '2-digit'
    });
}

module.exports = { prettyDate };