import os
import requests
import asyncio
import discord
from discord.ext import commands

# Add the bot:
# https://discord.com/api/oauth2/authorize?client_id=861966798664761374&permissions=2147601408&scope=bot

# Setting Up
token = '*** YOUR TOKEN ***'
vt_token = '147eac96e8a588d37164c584cdbc9f28d2138558ce7965ffc357dcf29215d963'
bot = commands.Bot(command_prefix='/')

@bot.command()
async def vtscan(ctx, *args):
	if ctx.message.attachments:
		isfile = True

		await ctx.send(':dvd: **Downloading file...**')
		file = ctx.message.attachments[0]
		await file.save(file.filename)

		await ctx.send(':outbox_tray: **Sending to VT...**')
		localfile = open(file.filename, 'rb')
		scanid = requests.post(
			'https://www.virustotal.com/api/v3/files',
			headers={'x-apikey': vt_token},
			files={'file': (file.filename, localfile)}
			).json()['data']['id']
		localfile.close()

		await ctx.send(':recycle: **Deleting file from server...**')
		os.remove(file.filename)
	else:
		isfile = False
		await ctx.send(':outbox_tray: **Sending to VT...**')

		scanid = requests.post(
			'https://www.virustotal.com/api/v3/urls',
			headers={'x-apikey': vt_token},
			data={'url': str(args[0])}
			).json()['data']['id']

	await ctx.send(':mag_right: **Scanning...**')
	scanresult = requests.get(
		f'https://www.virustotal.com/api/v3/analyses/{scanid}',
		headers={'x-apikey': vt_token}
		).json()['data']['attributes']

	while scanresult['status'] != 'completed':
		scanresult = requests.get(
			f'https://www.virustotal.com/api/v3/analyses/{scanid}',
			headers={'x-apikey': vt_token}
			).json()['data']['attributes']
		await asyncio.sleep(0.1)

	await ctx.send(':card_box: **Fetching scan results...**')
	stats = scanresult['stats']
	engines = int(stats['malicious']) + int(stats['undetected']) + int(stats['harmless'])
	scans = scanresult['results']

	ismalw = ':warning: marked as malicious'
	color = 0xf58f14

	trusted_engines_detect = False
	try:
		trusted_engines_detect = (
			(scans['Dr.Web']['result'] != 'clean' and scans['Dr.Web']['result'] != None) or \
			(scans['DrWeb']['result'] != 'clean' and scans['DrWeb']['result'] != None) or \
			(scans['BitDefender']['result'] != 'clean' and scans['BitDefender']['result'] != None)
			)
	except KeyError:
		pass

	if (stats['malicious'] > 3) or trusted_engines_detect:
		ismalw = ':x: Malware!'
		color = 0xd13434
	else:
		ismalw = ':white_check_mark: Clean'
		color = 0x36b338

	resultstr = ''
	i = 0

	show_engines = []
	if (len(args) > 1) and (not isfile):
		show_engines = str(args[1]).split(',')
	elif (len(args) > 0) and (isfile):
		show_engines = str(args[0]).split(',')

	for engine in scans:
		if (not show_engines) and (i < 10):
			resultstr += f'**{engine}** - `{scans[engine]["result"]}`\n'
			i += 1
		elif (show_engines):
			for reqengine in show_engines:
				if reqengine == engine:
					resultstr += f'**{engine}** - `{scans[engine]["result"]}`\n'
		else:
			break

	scantype = 'file' if isfile else 'URL'
	resultmsg = discord.Embed(color=color, title=f'The {scantype} is {ismalw} ({stats["malicious"]}/{engines})', description=resultstr)
	await ctx.send(embed=resultmsg)

# Starting
bot.run(token)
