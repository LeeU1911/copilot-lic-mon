// Function to create a checkout session with Stripe
function createSaveNowCheckout(savingsAmount, csrfToken) {
    console.log("Creating checkout for savings amount:", savingsAmount);
    
    // Calculate the fee based on savings amount
    let feeAmount;
    if (savingsAmount > 500) {
        feeAmount = 100; // Flat $100 for savings > $500
    } else if (savingsAmount >= 100) {
        feeAmount = savingsAmount * 0.2; // 20% for savings between $100 and $500
    } else {
        feeAmount = savingsAmount * 0.4; // 40% for savings < $100
    }
    
    // Round to 2 decimal places
    feeAmount = Math.round(feeAmount * 100) / 100;
    
    console.log("Calculated fee amount:", feeAmount);
    
    // Create a form to submit the request
    const form = document.createElement('form');
    form.method = 'POST';
    form.action = window.location.href; // Use current URL
    
    // Add CSRF token
    const csrfInput = document.createElement('input');
    csrfInput.type = 'hidden';
    csrfInput.name = 'csrf_token';
    csrfInput.value = csrfToken;
    form.appendChild(csrfInput);
    
    // Add save_now parameter
    const saveNowInput = document.createElement('input');
    saveNowInput.type = 'hidden';
    saveNowInput.name = 'save_now';
    saveNowInput.value = '1';
    form.appendChild(saveNowInput);
    
    // Add savings amount
    const savingsInput = document.createElement('input');
    savingsInput.type = 'hidden';
    savingsInput.name = 'savings_amount';
    savingsInput.value = savingsAmount;
    form.appendChild(savingsInput);
    
    // Add fee amount
    const feeInput = document.createElement('input');
    feeInput.type = 'hidden';
    feeInput.name = 'fee_amount';
    feeInput.value = feeAmount;
    form.appendChild(feeInput);
    
    // Submit the form
    document.body.appendChild(form);
    console.log("Submitting form with data:", {
        csrf_token: csrfToken,
        save_now: '1',
        savings_amount: savingsAmount,
        fee_amount: feeAmount
    });
    form.submit();
}

// Add event listener when the DOM is fully loaded
document.addEventListener('DOMContentLoaded', function() {
    const saveNowButton = document.getElementById('save-now-button');
    if (saveNowButton) {
        saveNowButton.addEventListener('click', function(e) {
            e.preventDefault();
            const savingsAmount = parseFloat(saveNowButton.getAttribute('data-savings-amount'));
            const csrfToken = saveNowButton.getAttribute('data-csrf-token');
            createSaveNowCheckout(savingsAmount, csrfToken);
        });
    }
});

async function handleSaveNow() {
    const saveNowButton = document.getElementById('saveNowButton');
    const saveNowStatus = document.getElementById('saveNowStatus');
    
    try {
        saveNowButton.disabled = true;
        saveNowStatus.textContent = 'Processing payment...';
        
        const response = await fetch('/save-now', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                amount: parseFloat(document.getElementById('savingsAmount').textContent.replace('$', '')),
                githubOrg: document.getElementById('githubOrg').textContent
            })
        });
        
        const result = await response.json();
        
        if (result.success) {
            saveNowStatus.textContent = 'Payment successful! Disabling inactive seats...';
            
            // Wait for the webhook to process and disable seats
            setTimeout(async () => {
                try {
                    const statusResponse = await fetch(`/check-seat-disabling-status?payment_id=${result.payment_intent_id}`);
                    const statusResult = await statusResponse.json();
                    
                    if (statusResult.success) {
                        saveNowStatus.textContent = `Successfully disabled ${statusResult.seats_disabled} inactive seats. Total savings: $${statusResult.savings_amount}`;
                        // Refresh the page to update the UI
                        setTimeout(() => {
                            window.location.reload();
                        }, 3000);
                    } else {
                        saveNowStatus.textContent = 'Error checking seat disabling status: ' + statusResult.error;
                    }
                } catch (error) {
                    console.error('Error checking seat disabling status:', error);
                    saveNowStatus.textContent = 'Error checking seat disabling status. Please contact support.';
                }
            }, 5000); // Wait 5 seconds for the webhook to process
        } else {
            saveNowStatus.textContent = 'Error: ' + result.error;
            saveNowButton.disabled = false;
        }
    } catch (error) {
        console.error('Error processing payment:', error);
        saveNowStatus.textContent = 'Error processing payment. Please try again.';
        saveNowButton.disabled = false;
    }
} 