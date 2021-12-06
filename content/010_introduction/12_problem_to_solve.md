---
title: "The Technical Challenge"
chapter: true
draft: false
weight: 12
---
# What is the problem

## What is Software Composition Analysis(SCA)?
Software Composition Analysis (SCA) is a segment of application security testing that deals with managing the open source components used in a project. SCA tools perfrom automated scans of an app's code base including related artifacts such as containers and registries, to identify all open source components, their license compliance data, and any security vulnerabilities.

## Problem to solve
As developers continue to write code, software packages are used. These software packages then in turn utilize other open source packages. The developers are focused on making their code work, through functionalities provided by these software packages. As code packages are authored by people around the world, with varied backgrounds, the diligence towards code's security is not necessarily consistent. 
In order to provide consistent security visibility across all the code being developed by your team, you need to identify vulnerabilities in 3rd party packages being used in the code early. The earlier you identify these risky packages, the quicker you can take decision on addressing the risks.

## How are we doing it in this workshop?
In this workshop we will be focusing on implementing Snyk as a SCA scanner which is linked to AWS Code Suite tools such as Code Artifact, Code Commit, Elastic Container Registry to identify risks upon commits. Each section of this workshop will utilize AWS Cloud Development Kit(CDK) to setup infrastructure-as-code in your AWS account.
