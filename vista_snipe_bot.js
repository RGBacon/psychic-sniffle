// 🎯 VISTA AUCTION SNIPE BOT
// Multi-auction monitoring and automatic last-minute bidding

console.log("🎯 VISTA AUCTION SNIPE BOT LOADED");
console.log("=".repeat(50));

class VistaSnipeBot {
    constructor() {
        this.auctions = new Map(); // auctionId -> auctionData
        this.monitors = new Map(); // auctionId -> monitorInterval
        this.snipeTime = 0.5; // minutes before end to start monitoring (30 seconds)
        this.bidInterval = 5; // seconds between bid attempts (more aggressive)
        this.maxRetries = 5; // max bid attempts per auction (more attempts)
        this.finalBidTime = 30; // seconds before end to place final bid
    }

    // Add auction to snipe list
    addAuction(auctionId, maxBid, description = '') {
        console.log(`🎯 Adding auction ${auctionId} with max bid $${maxBid}`);
        
        // Validate max bid amount
        const bidAmount = parseFloat(maxBid);
        if (isNaN(bidAmount) || bidAmount <= 0) {
            console.log(`❌ Invalid bid amount: $${maxBid}. Must be a positive number.`);
            return;
        }
        
        this.auctions.set(auctionId, {
            id: auctionId,
            maxBid: bidAmount,
            description: description,
            currentPrice: 0,
            minBid: 0,
            endTime: null,
            status: 'pending',
            bidAttempts: 0,
            lastChecked: null
        });

        console.log(`✅ Auction ${auctionId} added to snipe list`);
        this.showAuctions();
    }

    // Remove auction from snipe list
    removeAuction(auctionId) {
        if (this.auctions.has(auctionId)) {
            this.auctions.delete(auctionId);
            this.stopMonitoring(auctionId);
            console.log(`🗑️ Auction ${auctionId} removed from snipe list`);
        }
        this.showAuctions();
    }

    // Get auction info and calculate end time
    async getAuctionInfo(auctionId) {
        try {
            const response = await fetch(`https://vistaauction.com/Event/LotDetails/${auctionId}`, {
                credentials: 'include'
            });
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }

            const html = await response.text();
            
            // Extract current price
            const currentPriceMatch = html.match(/<span class="detail__price--current[^>]*>\s*\$<span class="NumberPart">([^<]+)<\/span>/);
            const currentPrice = currentPriceMatch ? parseFloat(currentPriceMatch[1]) : 0;
            
            // Extract minimum bid
            const minBidMatch = html.match(/<span class="Bidding_Listing_MinPrice[^>]*>\s*\$<span class="NumberPart">([^<]+)<\/span>/);
            const minBid = minBidMatch ? parseFloat(minBidMatch[1]) : 0;
            
            // Extract time remaining
            const timeMatch = html.match(/<span class="detail__time[^>]*>\s*([^<]+)\s*<\/span>/);
            let endTime = null;
            
            if (timeMatch) {
                const timeStr = timeMatch[1].trim();
                console.log(`🔍 Raw time string: "${timeStr}"`);
                
                const hoursMatch = timeStr.match(/(\d+)\s*Hours?/);
                const minutesMatch = timeStr.match(/(\d+)\s*Minutes?/);
                const secondsMatch = timeStr.match(/(\d+)\s*Seconds?/);
                
                console.log(`🔍 Time matches - Hours: ${hoursMatch ? hoursMatch[1] : 'none'}, Minutes: ${minutesMatch ? minutesMatch[1] : 'none'}, Seconds: ${secondsMatch ? secondsMatch[1] : 'none'}`);
                
                if (hoursMatch || minutesMatch || secondsMatch) {
                    const hours = hoursMatch ? parseInt(hoursMatch[1]) : 0;
                    const minutes = minutesMatch ? parseInt(minutesMatch[1]) : 0;
                    const seconds = secondsMatch ? parseInt(secondsMatch[1]) : 0;
                    const totalSeconds = hours * 3600 + minutes * 60 + seconds;
                    
                    endTime = new Date(Date.now() + totalSeconds * 1000);
                    
                    console.log(`🔍 Calculated time - Hours: ${hours}, Minutes: ${minutes}, Seconds: ${seconds}, Total: ${totalSeconds}s`);
                    console.log(`🔍 End time: ${endTime.toLocaleString()}`);
                }
            }

            // Check if auction is active
            const isActive = html.includes('Submit Max Bid');
            
            return {
                currentPrice,
                minBid,
                endTime,
                isActive,
                html
            };
            
        } catch (error) {
            console.error(`❌ Error getting auction ${auctionId}:`, error);
            return null;
        }
    }

    // Check if auction is worth bidding on
    isWorthBidding(auctionId) {
        const auction = this.auctions.get(auctionId);
        if (!auction) return false;
        
        // If current price is already over our max, remove it
        if (auction.currentPrice >= auction.maxBid) {
            console.log(`🚫 Auction ${auctionId} current price $${auction.currentPrice} is over max bid $${auction.maxBid}`);
            this.removeAuction(auctionId);
            return false;
        }
        
        // Check if our max bid is high enough to meet minimum bid requirement
        if (auction.minBid > 0 && auction.maxBid < auction.minBid) {
            console.log(`🚫 Auction ${auctionId} max bid $${auction.maxBid} is below minimum bid $${auction.minBid}`);
            this.removeAuction(auctionId);
            return false;
        }
        
        return true;
    }

    // Start monitoring an auction
    startMonitoring(auctionId) {
        if (this.monitors.has(auctionId)) {
            return; // Already monitoring
        }

        console.log(`👀 Starting monitoring for auction ${auctionId}`);
        
        const monitor = setInterval(async () => {
            await this.checkAuction(auctionId);
        }, 30000); // Check every 30 seconds
        
        this.monitors.set(auctionId, monitor);
    }

    // Stop monitoring an auction
    stopMonitoring(auctionId) {
        const monitor = this.monitors.get(auctionId);
        if (monitor) {
            clearInterval(monitor);
            this.monitors.delete(auctionId);
            console.log(`⏹️ Stopped monitoring auction ${auctionId}`);
        }
    }

    // Check auction status and decide when to snipe
    async checkAuction(auctionId) {
        const auction = this.auctions.get(auctionId);
        if (!auction) return;

        console.log(`🔍 Checking auction ${auctionId}...`);
        
        const info = await this.getAuctionInfo(auctionId);
        if (!info) return;

        // Update auction data
        auction.currentPrice = info.currentPrice;
        auction.minBid = info.minBid;
        auction.endTime = info.endTime;
        auction.lastChecked = new Date();
        auction.status = info.isActive ? 'active' : 'ended';

        console.log(`📊 Auction ${auctionId}: Current $${auction.currentPrice}, Min Bid $${auction.minBid}`);

        // Check if worth bidding
        if (!this.isWorthBidding(auctionId)) {
            return;
        }

        // Check if it's time to start sniping
        if (auction.endTime && info.isActive) {
            const timeUntilEnd = (auction.endTime - Date.now()) / 1000; // seconds
            
            console.log(`🔍 Auction ${auctionId} time check: ${this.formatTimeRemaining(auction.endTime)} remaining (${timeUntilEnd.toFixed(1)}s)`);
            
            if (timeUntilEnd <= this.snipeTime * 60 && timeUntilEnd > 0) {
                console.log(`🚨 SNIPE TIME! Auction ${auctionId} ends in ${this.formatTimeRemaining(auction.endTime)}`);
                this.startSnipe(auctionId);
            }
        }
    }

    // Start the actual sniping process
    startSnipe(auctionId) {
        const auction = this.auctions.get(auctionId);
        if (!auction) return;

        console.log(`🎯 Starting snipe for auction ${auctionId} at $${auction.maxBid}`);
        
        // Stop regular monitoring, start aggressive sniping
        this.stopMonitoring(auctionId);
        
        // Calculate when to place the final bid (30 seconds before end)
        const timeUntilEnd = (auction.endTime - Date.now()) / 1000; // seconds
        
        // If we're already within 30 seconds, place bid immediately
        if (timeUntilEnd <= this.finalBidTime) {
            console.log(`🚨 URGENT: Auction ${auctionId} ends in ${this.formatTimeRemaining(auction.endTime)} - Placing bid immediately!`);
            this.placeFinalBid(auctionId);
            return;
        }
        
        // Calculate delay for final bid (30 seconds before end)
        const delayUntilFinalBid = (timeUntilEnd - this.finalBidTime) * 1000; // milliseconds
        
        console.log(`⏰ Final bid scheduled in ${this.formatTimeRemaining(new Date(Date.now() + delayUntilFinalBid))}`);
        
        // Schedule the final bid at exactly 30 seconds before end
        setTimeout(async () => {
            this.placeFinalBid(auctionId);
        }, delayUntilFinalBid);
        
        // Also place competitive bids if we have time
        if (timeUntilEnd > this.finalBidTime + 30) { // If more than 1 minute left
            const competitiveBidInterval = setInterval(async () => {
                if (auction.bidAttempts >= this.maxRetries || !this.isWorthBidding(auctionId)) {
                    clearInterval(competitiveBidInterval);
                    return;
                }
                
                const currentTimeUntilEnd = (auction.endTime - Date.now()) / 1000;
                
                // Stop competitive bidding when we're 30 seconds away
                if (currentTimeUntilEnd <= this.finalBidTime) {
                    clearInterval(competitiveBidInterval);
                    return;
                }
                
                // Place a competitive bid
                console.log(`⚡ Competitive bid! Auction ${auctionId} ends in ${this.formatTimeRemaining(auction.endTime)}`);
                await this.placeBid(auctionId, auction.maxBid);
                auction.bidAttempts++;
                
            }, this.bidInterval * 1000);
        }
    }
    
    // Helper method to place final bid
    async placeFinalBid(auctionId) {
        const auction = this.auctions.get(auctionId);
        if (!auction) return;
        
        if (!this.isWorthBidding(auctionId)) {
            console.log(`❌ Auction ${auctionId} no longer worth bidding on`);
            return;
        }
        
        const currentTimeUntilEnd = (auction.endTime - Date.now()) / 1000;
        console.log(`🚀 FINAL BID! Auction ${auctionId} ends in ${this.formatTimeRemaining(auction.endTime)} - Placing max bid!`);
        
        const result = await this.placeBid(auctionId, auction.maxBid);
        auction.bidAttempts++;
        
        if (result && result.Status === 'WINNING') {
            console.log(`🎉 SUCCESS! Final bid won auction ${auctionId}!`);
            this.removeAuction(auctionId);
        } else if (result && result.Status === 'LOSING') {
            console.log(`✅ Final bid placed successfully! You're not winning auction ${auctionId} (Next price: $${result.NextPrice || 'unknown'})`);
        } else if (result && result.Status === 'Success') {
            console.log(`✅ Final bid placed successfully on auction ${auctionId}`);
        } else {
            console.log(`⚠️ Final bid placed but response unclear:`, result);
        }
        
        console.log(`✅ Final bid placed for auction ${auctionId} - Snipe complete`);
    }

    // Helper: wait for SignalR ListingActionResponse for a specific listing
    waitForActionResponse(listingId, timeoutMs = 3500) {
        return new Promise((resolve) => {
            try {
                const $jq = window.jQuery || window.$;
                if (!$jq || typeof $jq !== 'function') {
                    resolve(null);
                    return;
                }
                let settled = false;
                const handler = function (event, data) {
                    if (settled) return;
                    if (data && String(data.Action_ListingID) === String(listingId)) {
                        settled = true;
                        $jq(document).off('SignalR_ListingActionResponse', handler);
                        resolve(data);
                    }
                };
                $jq(document).on('SignalR_ListingActionResponse', handler);
                setTimeout(() => {
                    if (settled) return;
                    settled = true;
                    try { $jq(document).off('SignalR_ListingActionResponse', handler); } catch (_) {}
                    resolve(null);
                }, timeoutMs);
            } catch (_) {
                resolve(null);
            }
        });
    }

    // Helper: normalize SignalR response into a consistent shape
    normalizeSignalRBidResponse(signalRData) {
        if (!signalRData) return null;
        const status = signalRData.Accepted ? 'Success'
            : (signalRData.Error || signalRData.ReasonCode ? 'Error' : 'Unknown');
        return {
            Status: status,
            NextPrice: signalRData.NextPrice,
            MaxBidAmount: signalRData.MaxBidAmount,
            ReasonCode: signalRData.ReasonCode,
            Message: signalRData.Message,
            Raw: signalRData
        };
    }

    // Place a bid
    async placeBid(auctionId, bidAmount) {
        console.log(`🚀 Placing bid $${bidAmount} on auction ${auctionId}`);
        
        try {
            const baseUrl = "https://vistaauction.com/Listing/Action";
            const params = new URLSearchParams({
                'ListingID': auctionId,
                'ListingType': 'Auction',
                'BidAmount': bidAmount,
                'BuyItNow': 'false',
                '_': Date.now()
            });
            
            const url = `${baseUrl}?${params.toString()}`;
            console.log(`🌐 Bid URL: ${url}`);

            // Start listening for SignalR response before firing the request
            const signalrPromise = this.waitForActionResponse(auctionId, 4000).catch(() => null);
            
            const response = await fetch(url, {
                method: 'GET',
                credentials: 'include',
                headers: {
                    'Accept': 'application/json, text/javascript, */*; q=0.01',
                    'X-Requested-With': 'XMLHttpRequest'
                }
            });
            
            console.log(`📡 Response status: ${response.status} ${response.statusText}`);
            console.log(`📡 Response headers:`, Object.fromEntries(response.headers.entries()));
            
            const data = await response.text();
            console.log(`📋 Raw bid response for ${auctionId}:`, data);
            
            // Try to parse as JSON first
            try {
                const jsonData = JSON.parse(data);
                console.log(`📋 Parsed bid response for ${auctionId}:`, jsonData);
                console.log(`📋 Response details - Status: ${jsonData.Status}, NextPrice: $${jsonData.NextPrice || 'N/A'}, MaxBidAmount: $${jsonData.MaxBidAmount || 'N/A'}`);
                
                if (jsonData.Status === 'WINNING') {
                    console.log(`🎉 SUCCESS! You're winning auction ${auctionId}!`);
                    this.removeAuction(auctionId);
                } else if (jsonData.Status === 'LOSING') {
                    console.log(`✅ Bid placed successfully! You're not winning auction ${auctionId} (Next price: $${jsonData.NextPrice || 'unknown'})`);
                } else if (jsonData.Status === 'Success') {
                    console.log(`✅ Bid placed successfully on auction ${auctionId}`);
                } else {
                    console.log(`⚠️ Bid response received but status unclear:`, jsonData);
                }
                
                return jsonData;
                
            } catch (e) {
                // If not JSON, prefer the SignalR event if it arrives shortly after
                const signalData = await Promise.race([
                    signalrPromise,
                    new Promise((res) => setTimeout(() => res(null), 1200))
                ]);
                if (signalData) {
                    console.log('📡 SignalR ListingActionResponse:', signalData);
                    const normalized = this.normalizeSignalRBidResponse(signalData);
                    console.log('📋 Normalized SignalR bid response:', normalized);
                    return normalized;
                }

                // Fallback heuristics on response text
                const lowerData = (data || '').toLowerCase();
                if (lowerData.includes('success') || lowerData.includes('ok') || lowerData.includes('accepted') || lowerData.includes('bid placed')) {
                    console.log(`✅ Bid appears successful (non-JSON response): ${data}`);
                    return { Status: 'Success', Message: data };
                } else if (lowerData.includes('error') || lowerData.includes('failed') || lowerData.includes('rejected') || lowerData.includes('invalid')) {
                    console.log(`❌ Bid appears to have failed: ${data}`);
                    return { Status: 'Error', Message: data };
                } else if (lowerData.includes('already') || lowerData.includes('higher') || lowerData.includes('minimum')) {
                    console.log(`⚠️ Bid may have failed due to requirements: ${data}`);
                    return { Status: 'Requirements', Message: data };
                } else {
                    console.log(`⚠️ Unknown bid response format: ${data}`);
                    return { Status: 'Unknown', Message: data };
                }
            }
            
        } catch (error) {
            console.error(`❌ Error placing bid on ${auctionId}:`, error);
            return null;
        }
    }

    // Start monitoring all auctions
    startMonitoringAll() {
        console.log(`🚀 Starting monitoring for ${this.auctions.size} auctions...`);
        
        this.auctions.forEach((auction, auctionId) => {
            this.startMonitoring(auctionId);
        });
    }

    // Stop monitoring all auctions
    stopMonitoringAll() {
        console.log(`⏹️ Stopping all monitoring...`);
        
        this.auctions.forEach((auction, auctionId) => {
            this.stopMonitoring(auctionId);
        });
    }

    // Format time remaining in a human-readable format
    formatTimeRemaining(endTime) {
        if (!endTime) return 'unknown';
        
        const timeUntilEnd = Math.max(0, Math.floor((endTime - Date.now()) / 1000));
        
        if (timeUntilEnd === 0) return 'ended';
        
        const hours = Math.floor(timeUntilEnd / 3600);
        const minutes = Math.floor((timeUntilEnd % 3600) / 60);
        const seconds = timeUntilEnd % 60;
        
        if (hours > 0) {
            return `${hours}h ${minutes}m ${seconds}s`;
        } else if (minutes > 0) {
            return `${minutes}m ${seconds}s`;
        } else {
            return `${seconds}s`;
        }
    }

    // Show current auctions
    showAuctions() {
        console.log(`\n📋 CURRENT SNIPE LIST (${this.auctions.size} auctions):`);
        console.log("=".repeat(60));
        
        if (this.auctions.size === 0) {
            console.log("No auctions in snipe list");
            return;
        }
        
        this.auctions.forEach((auction, auctionId) => {
            const status = auction.status === 'active' ? '🟢' : '🔴';
            const timeLeft = auction.endTime ? 
                this.formatTimeRemaining(auction.endTime) : 'unknown';
            
            console.log(`${status} ${auctionId}: Max $${auction.maxBid} | Current $${auction.currentPrice} | Min $${auction.minBid} | Time: ${timeLeft} | ${auction.description}`);
        });
    }

    // Load auctions from a list
    loadAuctions(auctionList) {
        console.log(`📥 Loading ${auctionList.length} auctions...`);
        
        auctionList.forEach(item => {
            if (item.id && item.maxBid) {
                this.addAuction(item.id, item.maxBid, item.description || '');
            }
        });
        
        this.showAuctions();
    }

    // Clear all auctions
    clearAll() {
        console.log(`🗑️ Clearing all auctions...`);
        this.stopMonitoringAll();
        this.auctions.clear();
        this.showAuctions();
    }

    // Manual final bid trigger (emergency use)
    async manualFinalBid(auctionId) {
        const auction = this.auctions.get(auctionId);
        if (!auction) {
            console.log(`❌ Auction ${auctionId} not found in snipe list`);
            return;
        }

        console.log(`🚨 MANUAL FINAL BID TRIGGERED for auction ${auctionId} at $${auction.maxBid}`);
        
        // Get current auction info to check timing
        const info = await this.getAuctionInfo(auctionId);
        if (!info || !info.isActive) {
            console.log(`❌ Auction ${auctionId} is not active`);
            return;
        }

        if (auction.endTime) {
            const timeUntilEnd = (auction.endTime - Date.now()) / 1000;
            console.log(`⏰ Auction ends in ${this.formatTimeRemaining(auction.endTime)}`);
            
            if (timeUntilEnd <= 0) {
                console.log(`❌ Auction ${auctionId} has already ended`);
                return;
            }
        }

        // Place the bid immediately
        const result = await this.placeBid(auctionId, auction.maxBid);
        
        if (result && result.Status === 'WINNING') {
            console.log(`🎉 SUCCESS! Manual bid won auction ${auctionId}!`);
            this.removeAuction(auctionId);
        }
        
        return result;
    }

    // Validate and update bid if needed
    async validateAndUpdateBid(auctionId) {
        const auction = this.auctions.get(auctionId);
        if (!auction) return false;

        // Get current auction info
        const info = await this.getAuctionInfo(auctionId);
        if (!info) return false;

        // Update auction data
        auction.currentPrice = info.currentPrice;
        auction.minBid = info.minBid;

        // Check if our bid is still valid
        if (auction.maxBid < auction.minBid) {
            console.log(`⚠️ WARNING: Auction ${auctionId} max bid $${auction.maxBid} is below minimum bid $${auction.minBid}`);
            console.log(`💡 Consider updating your max bid to at least $${auction.minBid}`);
            return false;
        }

        if (auction.currentPrice >= auction.maxBid) {
            console.log(`⚠️ WARNING: Auction ${auctionId} current price $${auction.currentPrice} is at or above your max bid $${auction.maxBid}`);
            return false;
        }

        return true;
    }

    // Update max bid for an auction
    updateMaxBid(auctionId, newMaxBid) {
        const auction = this.auctions.get(auctionId);
        if (!auction) {
            console.log(`❌ Auction ${auctionId} not found in snipe list`);
            return false;
        }

        const bidAmount = parseFloat(newMaxBid);
        if (isNaN(bidAmount) || bidAmount <= 0) {
            console.log(`❌ Invalid bid amount: $${newMaxBid}. Must be a positive number.`);
            return false;
        }

        const oldBid = auction.maxBid;
        auction.maxBid = bidAmount;
        
        console.log(`✅ Updated auction ${auctionId} max bid from $${oldBid} to $${bidAmount}`);
        this.showAuctions();
        return true;
    }
}

// Create global bot instance
const snipeBot = new VistaSnipeBot();

// Helper functions for easy use
function addAuction(id, maxBid, description = '') {
    snipeBot.addAuction(id, maxBid, description);
}

function removeAuction(id) {
    snipeBot.removeAuction(id);
}

function startMonitoring() {
    snipeBot.startMonitoringAll();
}

function stopMonitoring() {
    snipeBot.stopMonitoringAll();
}

function showAuctions() {
    snipeBot.showAuctions();
}

function clearAll() {
    snipeBot.clearAll();
}

function updateMaxBid(auctionId, newMaxBid) {
    return snipeBot.updateMaxBid(auctionId, newMaxBid);
}

function validateBid(auctionId) {
    return snipeBot.validateAndUpdateBid(auctionId);
}

function manualBid(auctionId) {
    return snipeBot.manualFinalBid(auctionId);
}

// Example usage
console.log(`
🎯 SNIPE BOT COMMANDS:
======================

// Add auctions to snipe list
addAuction("1640789294", 20.00, "Cat Litter")
addAuction("1640789295", 15.00, "Another Item")

// Start monitoring all auctions
startMonitoring()

// Stop monitoring
stopMonitoring()

// Show current auctions
showAuctions()

// Remove specific auction
removeAuction("1640789294")

// Clear all auctions
clearAll()

// Update max bid for an auction
updateMaxBid("1640789294", 25.00)

// Validate bid before sniping
validateBid("1640789294")

// Manual emergency bid
manualBid("1640789294")

// Load multiple auctions at once
snipeBot.loadAuctions([
    {id: "1640789294", maxBid: 20.00, description: "Cat Litter"},
    {id: "1640789295", maxBid: 15.00, description: "Another Item"}
])

🔒 VALIDATION FEATURES:
=======================
✅ Checks if max bid > minimum bid requirement
✅ Automatically removes auctions with invalid bids
✅ Validates bid amounts when adding auctions
✅ Warns about bids that are too low
✅ Allows updating max bids during monitoring
`);

// Auto-start monitoring
console.log("🚀 Auto-starting monitoring...");
startMonitoring();
